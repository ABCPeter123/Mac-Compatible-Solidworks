//! Hash-verified PA30 compatibility adapter. No integrity bypass.
//! The expected size and SHA-256 come from an independent Windows reference
//! for the exact authenticated original MSU. Never accept an unchecked output.
use ms_delta::{Error, Limits, pa30::{apply_pa30_with_verifier, apply_pa30_compat, inspect_pa30}};
use sha2::{Digest, Sha256};
use std::{env, fs, io::Write, path::Path};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 6 {
        return Err("expected source delta target size sha256".into());
    }
    let limit = Limits::default();
    let source = Path::new(&args[1]);
    let delta = Path::new(&args[2]);
    let output = Path::new(&args[3]);
    let size: usize = args[4].to_str().ok_or("invalid size")?.parse()?;
    let expected = args[5].to_str().ok_or("invalid hash")?;
    if (expected != "-" && (expected.len() != 64 || !expected.bytes().all(|c| c.is_ascii_hexdigit())))
        || size > limit.max_output_bytes || output.exists()
        || fs::symlink_metadata(output).is_ok()
        || fs::symlink_metadata(source)?.file_type().is_symlink()
        || fs::symlink_metadata(delta)?.file_type().is_symlink()
        || fs::metadata(source)?.len() > limit.max_source_bytes as u64
        || fs::metadata(delta)?.len() > limit.max_patch_bytes as u64 {
        return Err("invalid bounded inputs".into());
    }
    let source = fs::read(source)?;
    let delta = fs::read(delta)?;
    let info = inspect_pa30(&delta, &limit)?;
    if info.target_size != size {
        return Err("unexpected target size".into());
    }
    let reconstructed = if info.target_hash_algorithm == 0 && info.target_hash.is_empty() {
        if expected == "-" {
            return Err("hashless PA30 needs independent SHA256".into());
        }
        apply_pa30_with_verifier(&source, &delta, &limit, |bytes| {
            if bytes.len() != size || format!("{:x}", Sha256::digest(bytes)) != expected {
                return Err(Error::Integrity("independent Windows SHA256 or size mismatch"));
            }
            Ok(())
        })?
    } else {
        // Every compatibility candidate must pass the original PA30 hash.
        apply_pa30_compat(&source, &delta, &limit)?
    };
    if reconstructed.len() != size || (expected != "-" &&
            format!("{:x}", Sha256::digest(&reconstructed)) != expected) {
        return Err("independent target verification failed".into());
    }
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(output)?;
    f.write_all(&reconstructed)?;
    f.sync_all()?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        // No private path or original package bytes leave the helper.
        let _ = error;
        eprintln!("Verified PA30 reconstruction rejected");
        std::process::exit(1);
    }
}
