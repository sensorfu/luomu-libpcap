use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use libflate::gzip::Decoder;
use tar::Archive;

static VERSION: &str = "1.9.1";

fn main() -> io::Result<()> {
    let out_dir = env::var("OUT_DIR").expect("environment variable OUT_DIR");
    let source_dir = unpack_libpcap(&out_dir)?;
    compile(&out_dir, &source_dir)?;

    let libdir = format!("{}/lib", out_dir);

    println!("cargo:rustc-link-lib=static=pcap");
    println!("cargo:rustc-link-search=native={}", libdir);

    Ok(())
}

fn unpack_libpcap(out_dir: &str) -> io::Result<PathBuf> {
    eprintln!("*** UNPACK_LIBPCAP");
    let dest = format!("{}/src", out_dir);

    let base = format!("libpcap-{}", VERSION);
    let full = format!("{}.tar.gz", base);
    let fp = fs::File::open(full)?;

    let gunzipped = Decoder::new(fp)?;
    let mut untar = Archive::new(gunzipped);

    untar.unpack(&dest).or_else(|err| {
        // If already extracted, don't fail. Helps recompilations.
        if err.kind() == io::ErrorKind::AlreadyExists {
            return Ok(());
        }
        Err(err)
    })?;

    let ret = format!("{}/{}", dest, base);
    Ok(ret.into())
}

fn compile(out_dir: &str, source_dir: &Path) -> io::Result<()> {
    eprintln!("*** COMPILE");
    let target_arg = format!("--target={}", env::var("TARGET").unwrap());
    let host_arg = format!("--host={}", env::var("HOST").unwrap());
    let j_arg = format!("-j{}", env::var("NUM_JOBS").unwrap());

    let compiler = cc::Build::new().get_compiler();
    let cc = compiler.path().to_string_lossy();
    // panic!("cc = {}", cc);

    let output = Command::new(source_dir.join("configure"))
        .current_dir(&source_dir)
        .arg(format!("CC={}", cc))
        .arg("--prefix")
        .arg(&out_dir)
        .arg("--disable-universal")
        .arg("--enable-shared=no")
        .arg("--enable-usb=no")
        .arg("--without-libnl")
        .arg("--disable-dbus")
        .arg(target_arg)
        .arg(host_arg)
        .output()?;
    if !output.status.success() {
        panic!(
            "\nSTDOUT:\n{}\n\nSTDERR:\n{}\n",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = Command::new("make")
        .current_dir(&source_dir)
        .arg(j_arg)
        .output()?;
    if !output.status.success() {
        panic!(
            "\nSTDOUT:\n{}\n\nSTDERR:\n{}\n",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Command::new("make")
        .current_dir(&source_dir)
        .arg("install")
        .output()?;

    Ok(())
}
