use std::{env, path::PathBuf};

pub fn main() {
    println!("cargo::rerun-if-changed=src/c/core_helpers.c");
    println!("cargo::rerun-if-changed=src/c/core_helpers.h");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("`CARGO_CFG_TARGET_ARCH` should be set in a buildscript");

    if target_arch == "bpf" {
        build_helpers_bpf();
    } else {
        build_helpers_not_bpf();
    }

    generate_bindings();
}

fn build_helpers_bpf() {
    let endian = env::var("CARGO_CFG_TARGET_ENDIAN")
        .expect("`CARGO_CFG_TARGET_ENDIAN` should be set in a buildscript");

    let target = if endian == "little" {
        "bpfel"
    } else if endian == "big" {
        "bpfeb"
    } else {
        panic!("unsupported target endian");
    };

    let bitcode_file = cc::Build::new()
        .compiler("clang")
        .no_default_flags(true)
        .file("src/c/core_helpers.c")
        .flag("-g")
        .flag("-emit-llvm")
        .flag(format!("--target={}", target))
        .compile_intermediates()
        .into_iter()
        .next()
        .expect("bitcode file should be compiled");

    println!("cargo::rustc-link-arg={}", bitcode_file.display());
    println!("cargo::rustc-link-arg=--btf");

    // rustc-link-arg is not transitively propagated to dependent crates
    // they have to use this metadata in their buildscript
    println!("cargo::metadata=BITCODE_PATH={}", bitcode_file.display());
}

fn build_helpers_not_bpf() {
    cc::Build::default()
        .compiler("clang")
        .no_default_flags(true)
        .file("src/c/core_helpers.c")
        .flag("-flto=thin")
        .compile("core_helpers");
}

fn generate_bindings() {
    let bindings = bindgen::Builder::default()
        .use_core()
        .header("src/c/core_helpers.h")
        .generate()
        .expect("generating bindings should not fail");

    let out_dir = env::var("OUT_DIR").expect("`OUT_DIR` should be set in a buildscript");
    let out_file_path = PathBuf::from(out_dir).join("core_helpers.rs");

    bindings
        .write_to_file(out_file_path)
        .expect("writing bindings should not fail");
}
