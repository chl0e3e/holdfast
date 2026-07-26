//! Opt-in PAM password verification (ADRs 0015/0016).
//!
//! Deliberately small FFI over the stable libpam ABI: `pam_start` →
//! `pam_authenticate` → `pam_acct_mgmt` → `pam_end`, with a conversation that
//! answers echo-off prompts with the supplied password and fails closed on
//! anything else. No PAM session is opened and no credentials are installed,
//! so the ADR 0007 launch path stays PAM-free. Hand-written bindings avoid an
//! unmaintained wrapper-crate dependency (threat model T11); every error path
//! here denies. Consumed by both the SSH compatibility adapter and the
//! daemon's local issuer via [`crate::password::PasswordVerifier`].

use std::ffi::{c_char, c_int, c_void, CString};
use std::ptr;

use crate::password::PasswordVerifier;

/// The PAM service name used when none is configured
/// (`/etc/pam.d/holdfast-ssh`, shipped in `deploy/pam/`).
pub const DEFAULT_PAM_SERVICE: &str = "holdfast-ssh";
pub const MAX_PAM_SERVICE_BYTES: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum PamError {
    #[error(
        "PAM service name must be 1..={MAX_PAM_SERVICE_BYTES} bytes of ASCII letters, digits, \
         '-', '_' or non-leading '.'"
    )]
    InvalidServiceName,
}

// Linux-PAM ABI values (security/_pam_types.h).
const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;
const PAM_SILENT: c_int = 0x8000;
const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x1;
/// A conversation will never legitimately carry more prompts than this.
const MAX_CONV_MESSAGES: c_int = 32;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: unsafe extern "C" fn(
        c_int,
        *const *const PamMessage,
        *mut *mut PamResponse,
        *mut c_void,
    ) -> c_int,
    appdata_ptr: *mut c_void,
}

enum PamHandle {}

#[link(name = "pam")]
extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conversation: *const PamConv,
        handle: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_authenticate(handle: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_acct_mgmt(handle: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_end(handle: *mut PamHandle, status: c_int) -> c_int;
}

// PAM frees conversation responses with the C allocator, so they must be
// allocated with it. libc is always linked; no crate dependency is needed.
extern "C" {
    fn calloc(count: usize, size: usize) -> *mut c_void;
    fn free(pointer: *mut c_void);
    fn strdup(source: *const c_char) -> *mut c_char;
}

/// Free a partially or fully filled response array the way PAM would.
unsafe fn free_responses(responses: *mut PamResponse, count: usize) {
    for index in 0..count {
        let resp = (*responses.add(index)).resp;
        if !resp.is_null() {
            free(resp.cast());
        }
    }
    free(responses.cast());
}

/// Answers every echo-off prompt with the password carried in `appdata`
/// (a NUL-terminated C string). Echo-on or unknown prompt styles abort the
/// conversation rather than echoing or guessing.
unsafe extern "C" fn conversation(
    message_count: c_int,
    messages: *const *const PamMessage,
    out: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    if message_count <= 0
        || message_count > MAX_CONV_MESSAGES
        || messages.is_null()
        || out.is_null()
        || appdata.is_null()
    {
        return PAM_CONV_ERR;
    }
    let count = message_count as usize;
    let responses = calloc(count, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
    if responses.is_null() {
        return PAM_BUF_ERR;
    }
    for index in 0..count {
        let message = *messages.add(index);
        if message.is_null() {
            free_responses(responses, count);
            return PAM_CONV_ERR;
        }
        match (*message).msg_style {
            PAM_PROMPT_ECHO_OFF => {
                let answer = strdup(appdata as *const c_char);
                if answer.is_null() {
                    free_responses(responses, count);
                    return PAM_BUF_ERR;
                }
                (*responses.add(index)).resp = answer;
            }
            PAM_ERROR_MSG | PAM_TEXT_INFO => {} // calloc left resp null
            _ => {
                free_responses(responses, count);
                return PAM_CONV_ERR;
            }
        }
    }
    *out = responses;
    PAM_SUCCESS
}

/// Run one PAM authentication + account-management check. Any PAM error,
/// missing service configuration or interior NUL in an input denies.
fn authenticate(service: &CString, user: &str, password: &str) -> bool {
    let (Ok(user), Ok(password)) = (CString::new(user), CString::new(password)) else {
        return false;
    };
    let conv = PamConv {
        conv: conversation,
        appdata_ptr: password.as_ptr() as *mut c_void,
    };
    let mut handle: *mut PamHandle = ptr::null_mut();
    // SAFETY: `service`, `user`, `password` and `conv` are NUL-terminated or
    // repr(C) values that outlive every PAM call below; `handle` is only used
    // after a successful pam_start and always released with pam_end.
    unsafe {
        if pam_start(service.as_ptr(), user.as_ptr(), &conv, &mut handle) != PAM_SUCCESS
            || handle.is_null()
        {
            return false;
        }
        let flags = PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK;
        let mut status = pam_authenticate(handle, flags);
        if status == PAM_SUCCESS {
            status = pam_acct_mgmt(handle, flags);
        }
        pam_end(handle, status);
        status == PAM_SUCCESS
    }
}

/// [`PasswordVerifier`] backed by the host PAM stack.
pub struct PamVerifier {
    service: CString,
}

impl PamVerifier {
    /// The service name selects `/etc/pam.d/<service>`, so it is restricted to
    /// a bounded, path-safe character set.
    pub fn new(service: impl Into<String>) -> Result<Self, PamError> {
        let service = service.into();
        if service.is_empty()
            || service.len() > MAX_PAM_SERVICE_BYTES
            || service.starts_with('.')
            || !service
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(PamError::InvalidServiceName);
        }
        Ok(Self {
            service: CString::new(service).expect("validated service name has no NUL"),
        })
    }
}

impl PasswordVerifier for PamVerifier {
    fn verify(&self, user: &str, password: &str) -> bool {
        authenticate(&self.service, user, password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_names_are_validated() {
        PamVerifier::new(DEFAULT_PAM_SERVICE).unwrap();
        PamVerifier::new("sshd").unwrap();
        for invalid in [
            "",
            "../evil",
            "has space",
            ".hidden",
            "slash/name",
            &"x".repeat(MAX_PAM_SERVICE_BYTES + 1),
        ] {
            assert!(PamVerifier::new(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn interior_nul_in_credentials_fails_closed() {
        let verifier = PamVerifier::new(DEFAULT_PAM_SERVICE).unwrap();
        assert!(!verifier.verify("user\0name", "password"));
        assert!(!verifier.verify("username", "pass\0word"));
    }

    /// Round trip against a real local account. Needs root (to read shadow),
    /// an installed `/etc/pam.d/holdfast-ssh` and a throwaway account, so it
    /// is ignored here and driven by `tests/password-auth/run.sh`.
    #[test]
    #[ignore = "needs a real account and PAM service; run via tests/password-auth/run.sh"]
    fn real_account_round_trip() {
        let user = std::env::var("HOLDFAST_PAM_TEST_USER").expect("HOLDFAST_PAM_TEST_USER");
        let password =
            std::env::var("HOLDFAST_PAM_TEST_PASSWORD").expect("HOLDFAST_PAM_TEST_PASSWORD");
        let service = std::env::var("HOLDFAST_PAM_TEST_SERVICE")
            .unwrap_or_else(|_| DEFAULT_PAM_SERVICE.to_string());
        let verifier = PamVerifier::new(service).unwrap();
        assert!(
            verifier.verify(&user, &password),
            "correct password rejected"
        );
        assert!(
            !verifier.verify(&user, &format!("{password}-wrong")),
            "wrong password accepted"
        );
        assert!(!verifier.verify(&user, ""), "empty password accepted");
    }

    #[test]
    fn unknown_service_denies_via_real_pam() {
        // An unconfigured service falls through to /etc/pam.d/other (deny on
        // any sane host) or errors outright; both must come back false.
        let verifier = PamVerifier::new("holdfast-test-no-such-service").unwrap();
        assert!(!verifier.verify("root", "wrong-password"));
    }
}
