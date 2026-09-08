//! User-scoped Windows protection. Never falls back to plaintext.
use anyhow::{Context, Result};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    },
};

pub fn protect(bytes: &[u8]) -> Result<Vec<u8>> {
    transform(bytes, true)
}

pub fn unprotect(bytes: &[u8]) -> Result<Vec<u8>> {
    transform(bytes, false)
}

fn transform(bytes: &[u8], protect: bool) -> Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len().try_into().context("DPAPI input too large")?,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
    // SAFETY: input lives across this synchronous call; optional pointers are
    // null and output is initialized. No LOCAL_MACHINE flag: scope is the user.
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    anyhow::ensure!(
        ok != 0,
        "Windows credential protection failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: successful DPAPI calls allocate cbData bytes with LocalAlloc.
    // Copy before freeing, and wipe the Windows buffer (including plaintext).
    let result = unsafe {
        use zeroize::Zeroize;
        let buffer = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
        let result = buffer.to_vec();
        buffer.zeroize();
        LocalFree(output.pbData.cast());
        result
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_protection_round_trip_and_tamper_rejection() {
        let secret = b"holdfast-test-grant-and-shell-recovery-credential";
        let encrypted = protect(secret).unwrap();
        assert!(!encrypted.windows(secret.len()).any(|w| w == secret));
        assert_eq!(unprotect(&encrypted).unwrap(), secret);
        assert!(unprotect(&encrypted[..encrypted.len() / 2]).is_err());
        let mut damaged = encrypted;
        let last = damaged.len() - 1;
        damaged[last] ^= 0x80;
        assert!(unprotect(&damaged).is_err());
    }
}
