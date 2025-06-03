// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use std::{
    env, fs,
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use cargo_metadata::{
    Artifact, CompilerMessage, Message, Metadata, MetadataCommand, Package, Target,
};

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    // Add dependency on eBPF dir.
    let Metadata { packages, .. } = MetadataCommand::new().no_deps().exec().unwrap();
    let ebpf_package = packages
        .into_iter()
        .find(|Package { name, .. }| name.as_str() == "krsi-ebpf")
        .unwrap();
    let Package { manifest_path, .. } = ebpf_package;
    let ebpf_dir = manifest_path.parent().unwrap();
    println!("cargo:rerun-if-changed={}", ebpf_dir.as_str());

    // Evaluate bpf target (i.e.: bpf(eb|el)-unknown-none).
    let endian = env::var_os("CARGO_CFG_TARGET_ENDIAN").unwrap();
    let target = if endian == "big" {
        "bpfeb"
    } else if endian == "little" {
        "bpfel"
    } else {
        panic!("unsupported endian={:?}", endian)
    };
    let target = format!("{target}-unknown-none");

    // Create build command.
    let mut cmd = Command::new("cargo");
    cmd.env("CARGO_ENCODED_RUSTFLAGS", "-Cdebuginfo=2");
    cmd.args([
        "+nightly-2025-03-15",
        "build",
        "-Z",
        "build-std=core",
        "--bins",
        "--message-format=json",
        "--release",
        "--target",
        &target,
    ]);

    // Set bpf target arch on build command.
    let arch = env::var_os("CARGO_CFG_TARGET_ARCH").unwrap();
    cmd.env("CARGO_CFG_BPF_TARGET_ARCH", arch);

    // Workaround to make sure that the rust-toolchain.toml is respected.
    for key in ["RUSTUP_TOOLCHAIN", "RUSTC"] {
        cmd.env_remove(key);
    }
    cmd.current_dir(ebpf_dir);

    // Workaround for https://github.com/rust-lang/cargo/issues/6412 where cargo flocks itself.
    let ebpf_target_dir = out_dir.join("ebpf");
    cmd.arg("--target-dir").arg(&ebpf_target_dir);

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("failed to spawn {cmd:?}: {err}"));
    let Child { stdout, stderr, .. } = &mut child;

    // Trampoline stdout to cargo warnings.
    let stderr = stderr.take().unwrap();
    let stderr = BufReader::new(stderr);
    let stderr = std::thread::spawn(move || {
        for line in stderr.lines() {
            let line = line.unwrap();
            println!("cargo:warning={line}");
        }
    });

    let stdout = stdout.take().unwrap();
    let stdout = BufReader::new(stdout);
    let mut executables = Vec::new();
    for message in Message::parse_stream(stdout) {
        #[allow(clippy::collapsible_match)]
        match message.expect("valid JSON") {
            Message::CompilerArtifact(Artifact {
                executable,
                target: Target { name, .. },
                ..
            }) => {
                if let Some(executable) = executable {
                    executables.push((name, executable.into_std_path_buf()));
                }
            }
            Message::CompilerMessage(CompilerMessage { message, .. }) => {
                for line in message.rendered.unwrap_or_default().split('\n') {
                    println!("cargo:warning={line}");
                }
            }
            Message::TextLine(line) => {
                println!("cargo:warning={line}");
            }
            _ => {}
        }
    }

    let status = child
        .wait()
        .unwrap_or_else(|err| panic!("failed to wait for {cmd:?}: {err}"));
    assert_eq!(status.code(), Some(0), "{cmd:?} failed: {status:?}");

    stderr.join().map_err(std::panic::resume_unwind).unwrap();

    for (name, binary) in executables {
        let dst = out_dir.join(name);
        let _: u64 = fs::copy(&binary, &dst)
            .unwrap_or_else(|err| panic!("failed to copy {binary:?} to {dst:?}: {err}"));
    }
}
