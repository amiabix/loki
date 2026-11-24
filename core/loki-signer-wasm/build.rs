fn main() {
    println!("cargo::rustc-check-cfg=cfg(secp_c_unlinked)");
    for var in ["AR", "TARGET_AR", "AR_wasm32_unknown_unknown", "AR_wasm32-unknown-unknown", "CC", "TARGET_CC", "CC_wasm32_unknown_unknown", "CC_wasm32-unknown-unknown", "PATH"] {
        println!("cargo::rerun-if-env-changed={var}");
    }
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("wasm32") {
        return;
    }
    let archiver = cc::Build::new().get_archiver();
    let program = std::path::Path::new(archiver.get_program());
    let llvm_ar = program
        .file_name()
        .is_some_and(|name| name.to_string_lossy().contains("llvm-ar"));
    if !llvm_ar {
        println!("cargo::rustc-cfg=secp_c_unlinked");
    }
}
