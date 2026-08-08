fn main() {
    tauri_build::build();

    // The Windows loader resolves msquic.dll before main(), so the runtime
    // must sit beside hf-desktop.exe for both `tauri dev` and unbundled builds.
    // The NSIS bundle receives the same verified file through
    // tauri.windows.conf.json.
    #[cfg(windows)]
    {
        let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
        let source = manifest.join("resources/windows/msquic.dll");
        if !source.is_file() {
            panic!(
                "missing {}; run desktop/scripts/prepare-msquic.ps1 first",
                source.display()
            );
        }
        println!("cargo:rerun-if-changed={}", source.display());
        let mut profile_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
        for _ in 0..3 {
            profile_dir.pop();
        }
        std::fs::copy(&source, profile_dir.join("msquic.dll"))
            .expect("copy msquic.dll beside hf-desktop.exe");
    }
}
