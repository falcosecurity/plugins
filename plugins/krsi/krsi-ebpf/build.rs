use std::env;

use which::which;

fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("`CARGO_CFG_TARGET_ARCH` should be set in a buildscript");

    if target_arch == "bpf" {
        let bitcode_path = env::var("DEP_CORE_HELPERS_BITCODE_PATH")
            .expect("`DEP_CORE_HELPERS_BITCODE_PATH` should be set when importing `core-helpers`");

        println!("cargo:rerun-if-changed={bitcode_path}");
        println!("cargo:rustc-link-arg={bitcode_path}");
        println!("cargo:rustc-link-arg=--btf");
    }

    println!("cargo::rerun-if-changed=CARGO_CFG_BPF_TARGET_ARCH");
    if let Ok(arch) = env::var("CARGO_CFG_BPF_TARGET_ARCH") {
        println!("cargo::rustc-cfg=bpf_target_arch=\"{arch}\"");
    } else {
        let arch = env::var("HOST").unwrap();
        let mut arch = arch.split_once("-").map_or(&*arch, |x| x.0);
        if arch.starts_with("riscv64") {
            arch = "riscv64";
        }
        println!("cargo::rustc-cfg=bpf_target_arch=\"{arch}\"");
    }

    println!("cargo::rustc-check-cfg=cfg(bpf_target_arch, values(\"x86_64\",\"arm\",\"aarch64\",\"riscv64\",\"powerpc64\",\"s390x\"))");
}
