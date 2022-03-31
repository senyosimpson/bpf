use aya_gen::btf_types;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("metal-ebpf/src");
    let names = vec!["ethhdr", "iphdr"];
    println!("Creating bindings");
    let bindings = btf_types::generate(Path::new("/sys/kernel/btf/vmlinux"), &names, true)?;
    let mut out = File::create(dir.join("bindings.rs"))?;
    write!(out, "{}", bindings)?;
    println!("Done!");
    Ok(())
}