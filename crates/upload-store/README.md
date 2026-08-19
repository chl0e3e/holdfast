# Holdfast upload store

This crate owns the transport-independent, same-uid temporary upload writer.
It has no HTTP, QUIC, PTY, terminal-model, or desktop dependencies. Paths are
created relative to a pre-opened no-follow root directory, file contents are
streamed through explicit bounds and SHA-256, and incomplete uploads are
removed on every error or drop path.

Run its U2 verification from the repository root:

```sh
cargo test -p hf-upload-store --locked
```

The server does not advertise `CAPABILITY_FILE_TRANSFER` merely because this
crate is present; daemon integration is a later gated phase (ADR 0028).
