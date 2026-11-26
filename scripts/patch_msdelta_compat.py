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
    // The four observed failures are AMD64 .text bytes. Try instruction-
    // granular normalization rather than disabling whole PE transforms.
    if matches!(info.file_type, 8 | 32) && info.flags & 0x200 != 0 {
        for mode in 1..=23 {
            let result = pe::with_swcompat_operand_mode(mode, || {
                apply_once(source, &parsed, limits, false)
            });
            if let Ok(output) = result {
                verify_hash(info, &output)?;
                if output.len() != info.target_size {
                    return Err(Error::Integrity("PA30 compatibility target size"));
                }
                return Ok(output);
            }
        }
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
    let operand_counts = pe::swcompat_operand_differential(reference, &candidate);
    Ok(serde_json::json!({
        "operand_short_branch": operand_counts[0],
        "operand_near_branch": operand_counts[1],
        "operand_rip_disp": operand_counts[2],
        "operand_other_immediate": operand_counts[3],
        "operand_other_displacement": operand_counts[4],
        "operand_instruction_other": operand_counts[5],
        "operand_unclassified": operand_counts[6],
        "file_type": info.file_type, "flags": info.flags, "different": different,
        "runs": runs, "max_run": max_run, "near_e8": near_e8, "near_e9": near_e9,
        "source_same": source_same, "header": categories[0], "text": categories[1],
        "rdata": categories[2], "data": categories[3], "rsrc": categories[4],
        "reloc": categories[5], "unwind": categories[6], "other": categories[7],
    }))
}

'''



# All changes are scoped to the pinned AMD64 disassembly routine. Mode zero
# is the exact upstream implementation. Each alternate is separately checked
# against the immutable original PA30 target digest before any output exists.
PE_MODE = r'''
thread_local! {
    static SWCOMPAT_OPERAND_MODE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

pub(super) fn with_swcompat_operand_mode<T>(mode: u8, f: impl FnOnce() -> T) -> T {
    struct Restore(u8);
    impl Drop for Restore {
        fn drop(&mut self) {
            SWCOMPAT_OPERAND_MODE.with(|v| v.set(self.0));
        }
    }
    let prior = SWCOMPAT_OPERAND_MODE.with(|v| v.replace(mode));
    let _restore = Restore(prior);
    f()
}

/// Aggregate mismatch counts by decoded operand type; no code, bytes or
/// positions are returned. Only the native-reference diagnostic uses this.
#[cfg(feature = "cli")]
pub(super) fn swcompat_operand_differential(reference: &[u8], candidate: &[u8]) -> [u64; 7] {
    let mut counts = [0u64; 7];
    if reference.len() != candidate.len() || reference.len() > 64 * 1024 * 1024 {
        return counts;
    }
    // Build one bounded coverage bitmap to handle overlapping runtime functions.
    let mut covered = vec![false; reference.len()];
    let Ok(layout) = PeLayout::parse(reference) else { return counts; };
    if layout.machine != 0x8664 { return counts; }
    let Some((rva, size)) = layout.directory(3) else { return counts; };
    let Ok(table) = layout.offset(rva, size) else { return counts; };
    let mut remaining = reference.len().saturating_mul(4);
    for index in 0..size / 12 {
        let entry = table + index * 12;
        let (Ok(begin), Ok(end)) = (read32(reference, entry), read32(reference, entry + 4)) else { continue; };
        if end <= begin { continue; }
        let length = (end - begin) as usize;
        if length > remaining { break; }
        remaining -= length;
        let Ok(file) = layout.offset(begin, length) else { continue; };
        let mut decoder = Decoder::with_ip(64, &reference[file..file+length],
                                           u64::from(begin), DecoderOptions::NONE);
        while decoder.can_decode() {
            let position = decoder.position();
            let ins = decoder.decode();
            let len = ins.len();
            if len == 0 || position + len > length { break; }
            if ins.is_invalid() { continue; }
            let offsets = decoder.get_constant_offsets(&ins);
            let branch = (0..ins.op_count()).any(|i| ins.op_kind(i) == OpKind::NearBranch64);
            for j in 0..len {
                let loc = file + position + j;
                if covered[loc] || reference[loc] == candidate[loc] { continue; }
                covered[loc] = true;
                let in_imm = j >= offsets.immediate_offset() && j < offsets.immediate_offset() + offsets.immediate_size();
                let in_disp = j >= offsets.displacement_offset() && j < offsets.displacement_offset() + offsets.displacement_size();
                let category = if in_imm && branch && offsets.immediate_size() == 1 { 0 }
                    else if in_imm && branch { 1 }
                    else if in_disp && ins.is_ip_rel_memory_operand() { 2 }
                    else if in_imm { 3 }
                    else if in_disp { 4 }
                    else { 5 };
                counts[category] += 1;
            }
        }
    }
    for (i, (&a,&b)) in reference.iter().zip(candidate).enumerate() {
        if a != b && !covered[i] { counts[6] += 1; }
    }
    counts
}

'''

PE_ANCHOR = "fn disassemble(layout: &PeLayout, output: &mut [u8], hints: &[u8], used: &RiftTable) -> Result<()> {"
PE_OLD = r'''            if let Some(displacement) = displacement
                && instruction.encoding() != EncodingKind::VEX
            {
                let cell = file + position + displacement;
                let next = begin
                    .wrapping_add(position as u32)
                    .wrapping_add(size as u32);
                let destination = next.wrapping_add(read32(output, cell)?);
                write32(
                    output,
                    cell,
                    mapped(used, destination).wrapping_sub(mapped(used, next)),
                )?;
            }'''
PE_NEW = r'''            let mode = SWCOMPAT_OPERAND_MODE.with(|v| v.get());
            let branch = (0..instruction.op_count())
                .any(|index| instruction.op_kind(index) == OpKind::NearBranch64);
            let is_vex = instruction.encoding() == EncodingKind::VEX;
            let is_legacy = instruction.encoding() == EncodingKind::Legacy;
            let here = begin.wrapping_add(position as u32);
            let next = here.wrapping_add(size as u32);
            // Bits 0 and 1: short relative branch policies. Older AMD64
            // producers can normalize rel8 operands when the mapped value fits.
            if branch && constants.immediate_size() == 1 && mode & 3 != 0 {
                let cell = file + position + constants.immediate_offset();
                let old = output[cell] as i8 as i32;
                let destination = next.wrapping_add(old as u32);
                let base = if mode & 8 != 0 {
                    mapped(used, here).wrapping_add(size as u32)
                } else { mapped(used, next) };
                let relative = mapped(used, destination).wrapping_sub(base) as i32;
                if (-128..=127).contains(&relative) {
                    output[cell] = relative as i8 as u8;
                } else if mode & 3 == 2 {
                    output[cell] = relative as u8;
                }
            }
            // Bit 2 admits VEX RIP operands. Bit 4 instead restricts to
            // legacy encodings. Bit 3 uses a mapped instruction-start anchor.
            let permitted = if mode & 16 != 0 { is_legacy }
                else { !is_vex || mode & 4 != 0 };
            if let Some(displacement) = displacement && permitted {
                let cell = file + position + displacement;
                let destination = next.wrapping_add(read32(output, cell)?);
                let base = if mode & 8 != 0 {
                    mapped(used, here).wrapping_add(size as u32)
                } else { mapped(used, next) };
                write32(output, cell, mapped(used, destination).wrapping_sub(base))?;
            }'''


def patch_pe(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or path.name != "pe.rs":
        raise ValueError("Expected pinned upstream AMD64 source")
    text = path.read_text(encoding="utf-8")
    if text.count(PE_ANCHOR) != 1 or text.count(PE_OLD) != 1 or "SWCOMPAT_OPERAND_MODE" in text:
        raise ValueError("Unexpected or previously patched AMD64 source")
    path.write_text(text.replace(PE_ANCHOR, PE_MODE + PE_ANCHOR).replace(PE_OLD, PE_NEW),
                    encoding="utf-8")

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
    args = parser.parse_args()
    patch(args.source)
    patch_pe(args.source.parent / "pa30" / "pe.rs")
