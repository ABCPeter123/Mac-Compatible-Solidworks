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
    // E8 restoration differs across producers; try the exact alternate
    // interpretation only if the original digest still validates.
    let mut candidates = vec![info.flags ^ 1];
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


/// Private Windows-reference differential. Never returns candidate bytes.
/// The independent reference must match the original intrinsic digest.
/// A temporary parsed view suppresses validation solely to count differences
/// in memory; no caller can install, retain or accept the candidate.
#[cfg(feature = "cli")]
pub fn diagnose_pa30_reference(source: &[u8], delta: &[u8], reference: &[u8],
                               limits: &Limits) -> Result<serde_json::Value> {
    if source.len() > limits.max_source_bytes || reference.len() > limits.max_output_bytes {
        return Err(Error::Limit("PA30 diagnostic inputs"));
    }
    let parsed = parse(delta, limits)?;
    let info = &parsed.info;
    validate_hash(info)?;
    if reference.len() != info.target_size {
        return Err(Error::Integrity("diagnostic reference size"));
    }
    verify_hash(info, reference)?;
    let diagnostic = Parsed {
        info: Pa30Info { target_hash_algorithm: 0, target_hash: Vec::new(), ..info.clone() },
        preprocessing: parsed.preprocessing,
        patch: parsed.patch,
    };
    let candidate = apply_once(source, &diagnostic, limits, true)?;
    if candidate.len() != reference.len() {
        return Err(Error::Integrity("diagnostic candidate length"));
    }
    // Recognized PE file ranges only. Do not report offsets or section names.
    let mut sections = Vec::new();
    let mut header = 0usize;
    let read16 = |n: usize| reference.get(n..n.checked_add(2)?)
        .and_then(|v| v.try_into().ok()).map(u16::from_le_bytes);
    let read32 = |n: usize| reference.get(n..n.checked_add(4)?)
        .and_then(|v| v.try_into().ok()).map(u32::from_le_bytes);
    if reference.get(..2) == Some(b"MZ") {
        if let Some(nt) = read32(60).map(|v| v as usize) {
            if nt <= reference.len().saturating_sub(24) && reference.get(nt..nt+4) == Some(b"PE\0\0") {
                let optional = nt + 24;
                let table = optional + read16(nt+20).unwrap_or(0) as usize;
                header = (read32(optional+60).unwrap_or(0) as usize).min(reference.len());
                for i in 0..usize::from(read16(nt+6).unwrap_or(0)).min(96) {
                    let off = table + i*40;
                    if off > reference.len().saturating_sub(40) { break; }
                    let start = read32(off+20).unwrap_or(0) as usize;
                    let size = read32(off+16).unwrap_or(0) as usize;
                    let end = start.saturating_add(size).min(reference.len());
                    let name = &reference[off..off+8];
                    let category = if name.starts_with(b".text") { 1 }
                        else if name.starts_with(b".rdata") { 2 }
                        else if name.starts_with(b".data") { 3 }
                        else if name.starts_with(b".rsrc") { 4 }
                        else if name.starts_with(b".reloc") { 5 }
                        else if name.starts_with(b".pdata") || name.starts_with(b".xdata") { 6 }
                        else { 7 };
                    if start < end { sections.push((start, end, category)); }
                }
            }
        }
    }
    let mut different = 0u64;
    let mut runs = 0u64;
    let mut max_run = 0u64;
    let mut current = 0u64;
    let mut near_e8 = 0u64;
    let mut near_e9 = 0u64;
    let mut source_same = 0u64;
    let mut categories = [0u64; 8];
    for (i, (&actual, &expected)) in candidate.iter().zip(reference).enumerate() {
        if actual == expected {
            current = 0;
            continue;
        }
        different += 1;
        if current == 0 { runs += 1; }
        current += 1;
        max_run = max_run.max(current);
        let cat = if i < header { 0 } else {
            sections.iter().find(|(a,b,_)| i >= *a && i < *b).map(|v|v.2).unwrap_or(7)
        };
        categories[cat] += 1;
        let start = i.saturating_sub(4);
        if reference[start..i].contains(&0xe8) || candidate[start..i].contains(&0xe8) { near_e8 += 1; }
        if reference[start..i].contains(&0xe9) || candidate[start..i].contains(&0xe9) { near_e9 += 1; }
        if source.get(i) == Some(&actual) { source_same += 1; }
    }
    Ok(serde_json::json!({
        "file_type": info.file_type, "flags": info.flags, "different": different,
        "runs": runs, "max_run": max_run, "near_e8": near_e8, "near_e9": near_e9,
        "source_same": source_same, "header": categories[0], "text": categories[1],
        "rdata": categories[2], "data": categories[3], "rsrc": categories[4],
        "reloc": categories[5], "unwind": categories[6], "other": categories[7],
    }))
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
