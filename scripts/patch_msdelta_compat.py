"""Patch the pinned MIT decoder with bounded, hash-verified PE alternatives.

A Windows ApplyDeltaB oracle has verified the same source and patch for
four PA30 target digest failures. Older producers may interpret the PE
normalization flags differently. Try only known transform alternatives
and never modify the encoded patch bytes, target hash or target length.
The original apply_once must validate the original intrinsic hash.
"""
from pathlib import Path
import argparse

ANCHOR = "fn apply_parsed(source: &[u8], parsed: &Parsed<'_>, limits: &Limits) -> Result<Vec<u8>> {"
INSERT = r'''
/// Experimental compatibility for producer-dependent PE normalization.
/// The original digest is checked by every attempt; hashless input is refused.
pub fn apply_pa30_compat(source: &[u8], delta: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    if source.len() > limits.max_source_bytes {
        return Err(Error::Limit("PA30 source size"));
    }
    let parsed = parse(delta, limits)?;
    validate_hash(&parsed.info)?;
    let first = apply_parsed(source, &parsed, limits);
    if !matches!(first, Err(Error::Integrity(_))) {
        return first;
    }
    let info = &parsed.info;
    if !matches!(info.file_type, 2 | 4 | 8 | 16 | 32 | 64 | 128) {
        return first;
    }
    // Known source preprocessing flags in the pinned pe::preprocess_cli.
    // Do not alter compression framing, reserved flags or expected hash.
    let mut bits: Vec<u64> = vec![2, 4, 8, 16, 32, 0x2000];
    match info.file_type {
        2 | 16 => bits.extend([0x40, 0x80, 0x100]),
        8 | 32 => bits.extend([0x200, 0x400]),
        4 => bits.extend([0x800, 0x1000]),
        64 => bits.extend([0x80000, 0x100000]),
        128 => bits.extend([0x800000, 0x1000000]),
        _ => {}
    }
    if matches!(info.file_type, 2 | 4 | 8) {
        bits.extend([0x4000, 0x8000]);
    } else {
        bits.extend([0x200000, 0x400000]);
    }
    let mut candidates = Vec::new();
    for &bit in &bits {
        candidates.push(info.flags ^ bit);
    }
    // Clear pairs of enabled source transforms only.
    for (i, &a) in bits.iter().enumerate() {
        for &b in &bits[i + 1..] {
            if info.flags & (a | b) == a | b {
                candidates.push(info.flags & !(a | b));
            }
        }
    }
    // Some producer versions omit an entire group of executable transforms.
    for mask in [0x38, 0x1c0, 0x600, 0x1800, 0xc000, 0x600000] {
        if info.flags & mask != 0 {
            candidates.push(info.flags & !mask);
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for flags in candidates.into_iter().take(96) {
        if flags == info.flags || !seen.insert(flags) {
            continue;
        }
        let alternate = Parsed {
            info: Pa30Info { flags, ..info.clone() },
            preprocessing: parsed.preprocessing,
            patch: parsed.patch,
        };
        if let Ok(output) = apply_once(source, &alternate, limits, false) {
            // apply_once checks the original target digest. Independently
            // repeat that check here before returning any bytes.
            verify_hash(info, &output)?;
            if output.len() != info.target_size {
                return Err(Error::Integrity("PA30 compatibility target size"));
            }
            return Ok(output);
        }
    }
    first
}

'''


def patch(path: Path) -> None:
    if path.is_symlink() or path.name != "pa30.rs":
        raise ValueError("Expected pinned upstream PA30 source")
    text = path.read_text(encoding="utf-8")
    if text.count(ANCHOR) != 1 or "pub fn apply_pa30_compat(" in text:
        raise ValueError("Unexpected or previously patched upstream source")
    path.write_text(text.replace(ANCHOR, INSERT + ANCHOR), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    patch(parser.parse_args().source)
