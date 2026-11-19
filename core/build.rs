// Links the Apple Secure Enclave Swift backend when the `apple-enclave` feature is on
// (macOS only). Compiles core/enclave-spike/se_backend.swift to a dylib and links it so
// `src/signer/secure_element_apple.rs`'s FFI (`se_open_*`, `se_wrap/unwrap/close`) resolves.
use std::{env, process::Command};

fn main() {
    let apple = env::var_os("CARGO_FEATURE_APPLE_ENCLAVE").is_some();
    let macos = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos");
    if !(apple && macos) {
        return;
    }
    let out = env::var("OUT_DIR").expect("OUT_DIR");
    let src = "enclave-spike/se_backend.swift";
    println!("cargo:rerun-if-changed={src}");
    let dylib = format!("{out}/libse_backend.dylib");
    let status = Command::new("swiftc")
        .args([
            "-emit-library", "-o", &dylib, src,
            "-framework", "Security", "-framework", "Foundation",
            "-Xlinker", "-install_name", "-Xlinker", "@rpath/libse_backend.dylib",
        ])
        .status()
        .expect("run swiftc (is Xcode/CLT installed?)");
    assert!(status.success(), "swiftc failed to build se_backend.swift");
    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-lib=dylib=se_backend");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{out}");
}
