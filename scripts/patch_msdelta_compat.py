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
/// Baseline modes plus specific RIP-relative policies. The previous modes
/// remain first so the already recovered executable stays reproducible.
fn swcompat_operand_modes() -> Vec<u8> {
    let mut modes: Vec<u8> = (1..=23).collect();
    for policy in 1..=7 {
        for base in [0, 4, 8, 12] {
            modes.push((policy << 5) | base);
        }
    }
    modes
}

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
        for mode in swcompat_operand_modes() {
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
    // A single anomalous source operand can be reused hundreds of times.
    // Use the compressed provenance to try an instruction-local alternate
    // without altering all other correctly normalized operands.
    if let Ok(Some(output)) = swcompat_sparse_rip(source, &parsed, limits) {
        verify_hash(info, &output)?;
        return Ok(output);
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


// A source-origin trace is used only by the Windows-reference diagnostic.
// The ordinary reconstruction path retains the original codec output.
const SWCOMPAT_NO_ORIGIN: u32 = u32::MAX;
thread_local! {
    static SWCOMPAT_TRACE: std::cell::RefCell<Option<Vec<u32>>> = const { std::cell::RefCell::new(None) };
}

fn swcompat_trace_literal() {
    SWCOMPAT_TRACE.with(|v| {
        if let Some(trace) = v.borrow_mut().as_mut() { trace.push(SWCOMPAT_NO_ORIGIN); }
    });
}

fn swcompat_trace_copy(source_len: usize, output_len: usize, offset: usize, length: usize) {
    SWCOMPAT_TRACE.with(|v| {
        let mut active = v.borrow_mut();
        let Some(trace) = active.as_mut() else { return; };
        if trace.len() != output_len {
            *active = None;
            return;
        }
        for i in 0..length {
            let from = source_len + output_len + i - offset;
            let origin = if from < source_len { from as u32 }
                else { trace[from - source_len] };
            trace.push(origin);
        }
    });
}

/// Only algorithm-derived displacement alternatives are allowed. A candidate
/// stays private until the original embedded target digest verifies.
fn swcompat_sparse_rip(source: &[u8], parsed: &Parsed<'_>, limits: &Limits) -> Result<Option<Vec<u8>>> {
    let info = &parsed.info;
    if !matches!(info.file_type, 8 | 32) || info.flags & 0x200 == 0
        || info.flags & (1 | 0x0200_0000) != 0 || info.target_size > 16 * 1024 * 1024 {
        return Ok(None);
    }
    validate_hash(info)?;
    let diagnostic = Parsed {
        info: Pa30Info { target_hash_algorithm: 0, target_hash: Vec::new(), ..info.clone() },
        preprocessing: parsed.preprocessing, patch: parsed.patch,
    };
    // Absolute bound on bytes hashed across all alternative trials.
    let mut hash_budget = 8usize * 1024 * 1024 * 1024;
    for mode in [0u8, 4] {
        let previous = SWCOMPAT_TRACE.with(|v| v.replace(Some(Vec::with_capacity(info.target_size))));
        let (decoded, operands) = pe::with_swcompat_rip_capture(|| {
            pe::with_swcompat_operand_mode(mode, || apply_once(source, &diagnostic, limits, true))
        });
        let trace = SWCOMPAT_TRACE.with(|v| v.replace(previous));
        let Ok(mut output) = decoded else { continue; };
        let Some(trace) = trace else { continue; };
        if output.len() != trace.len() || output.len() != info.target_size { continue; }
        // Map only eligible operand bytes. Never enumerate arbitrary target
        // bytes. Bounded inverted indexes keep trial cost proportional to the
        // actual propagated output positions.
        let mut positions: std::collections::BTreeMap<u32, Vec<usize>> = std::collections::BTreeMap::new();
        for operand in &operands {
            for j in 0..4 { positions.entry(operand.cell + j).or_default(); }
        }
        for (i, &origin) in trace.iter().enumerate() {
            if let Some(list) = positions.get_mut(&origin) { list.push(i); }
        }
        let mut trials = Vec::new();
        for operand in operands {
            let weight: usize = (0..4).map(|j| positions.get(&(operand.cell+j)).map_or(0, Vec::len)).sum();
            if weight != 0 { trials.push((operand, weight)); }
        }
        // VEX cases and unusually reused source operands are most likely to
        // expose the observed producer-dependent normalization difference.
        trials.sort_unstable_by_key(|(op, weight)| (!op.vex, std::cmp::Reverse(*weight)));
        for (operand, _) in trials {
            let mut baseline = [None; 4];
            for j in 0..4 {
                if let Some(&p) = positions.get(&(operand.cell+j as u32)).and_then(|v| v.first()) {
                    baseline[j] = Some(output[p]);
                }
            }
            let mut seen = std::collections::BTreeSet::new();
            for value in operand.alternatives {
                let bytes = value.to_le_bytes();
                let key = std::array::from_fn::<u8,4,_>(|j| if baseline[j].is_some() { bytes[j] } else { 0 });
                if !seen.insert(key) || (0..4).all(|j| baseline[j].is_none_or(|b| b == bytes[j])) {
                    continue;
                }
                if output.len() > hash_budget { return Ok(None); }
                hash_budget -= output.len();
                for j in 0..4 {
                    if let Some(list) = positions.get(&(operand.cell+j as u32)) {
                        for &p in list { output[p] = bytes[j]; }
                    }
                }
                if verify_hash(info, &output).is_ok() {
                    return Ok(Some(output));
                }
                for j in 0..4 {
                    if let Some(b) = baseline[j] && let Some(list) = positions.get(&(operand.cell+j as u32)) {
                        for &p in list { output[p] = b; }
                    }
                }
            }
        }
    }
    Ok(None)
}

/// A recipe contains only source-location commitments and indexes into
/// algorithm-derived displacement alternatives, never reconstructed bytes.
/// It is specific to the original source and patch SHA256. The independent
/// reference is required for synthesis, but not for replay on Apple Silicon.
#[cfg(feature = "cli")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SwcompatRecipe {
    version: u8,
    source_sha256: String,
    patch_sha256: String,
    mode: u8,
    selectors: std::collections::BTreeMap<String, usize>,
}

#[cfg(feature = "cli")]
fn swcompat_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(feature = "cli")]
fn swcompat_operand_key(patch_hash: &str, cell: u32) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"swcompat-rip-recipe-v1:");
    hash.update(patch_hash.as_bytes());
    hash.update(cell.to_le_bytes());
    format!("{:x}", hash.finalize())
}

#[cfg(feature = "cli")]
fn swcompat_recipe_candidate(source: &[u8], parsed: &Parsed<'_>, limits: &Limits,
    mode: u8) -> Result<(Vec<u8>, Vec<u32>, Vec<pe::SwcompatRipOperand>)> {
    let info = &parsed.info;
    if !matches!(mode, 0 | 4) || !matches!(info.file_type, 8 | 32)
        || info.flags & 0x200 == 0 || info.flags & (1 | 0x0200_0000) != 0
        || info.target_size > 16 * 1024 * 1024 {
        return Err(Error::Unsupported("RIP recipe format"));
    }
    validate_hash(info)?;
    let diagnostic = Parsed {
        info: Pa30Info { target_hash_algorithm: 0, target_hash: Vec::new(), ..info.clone() },
        preprocessing: parsed.preprocessing, patch: parsed.patch,
    };
    let previous = SWCOMPAT_TRACE.with(|v| v.replace(Some(Vec::with_capacity(info.target_size))));
    let (decoded, operands) = pe::with_swcompat_rip_capture(|| {
        pe::with_swcompat_operand_mode(mode, || apply_once(source, &diagnostic, limits, true))
    });
    let trace = SWCOMPAT_TRACE.with(|v| v.replace(previous));
    let output = decoded?;
    let trace = trace.ok_or(Error::Invalid("RIP recipe provenance"))?;
    if output.len() != trace.len() || output.len() != info.target_size {
        return Err(Error::Integrity("RIP recipe length"));
    }
    Ok((output, trace, operands))
}

#[cfg(feature = "cli")]
fn swcompat_replay_recipe(source: &[u8], delta: &[u8], limits: &Limits,
    recipe: &SwcompatRecipe) -> Result<Vec<u8>> {
    if recipe.version != 1 || recipe.selectors.is_empty() || recipe.selectors.len() > 512
        || recipe.source_sha256 != swcompat_digest(source)
        || recipe.patch_sha256 != swcompat_digest(delta) {
        return Err(Error::Integrity("RIP recipe identity"));
    }
    let parsed = parse(delta, limits)?;
    let (mut output, trace, operands) = swcompat_recipe_candidate(source, &parsed, limits, recipe.mode)?;
    let mut used = std::collections::BTreeSet::new();
    let mut overrides = std::collections::BTreeMap::new();
    for operand in operands {
        let key = swcompat_operand_key(&recipe.patch_sha256, operand.cell);
        let Some(&choice) = recipe.selectors.get(&key) else { continue; };
        let value = operand.alternatives.get(choice).ok_or(Error::Invalid("RIP recipe selector"))?;
        if !used.insert(key) { return Err(Error::Invalid("RIP recipe duplicate operand")); }
        for (j, byte) in value.to_le_bytes().into_iter().enumerate() {
            if let Some(prior) = overrides.insert(operand.cell + j as u32, byte) && prior != byte {
                return Err(Error::Integrity("RIP recipe conflicting operands"));
            }
        }
    }
    if used.len() != recipe.selectors.len() {
        return Err(Error::Invalid("RIP recipe unmatched selector"));
    }
    for (i, &origin) in trace.iter().enumerate() {
        if let Some(&byte) = overrides.get(&origin) { output[i] = byte; }
    }
    verify_hash(&parsed.info, &output)?;
    Ok(output)
}

#[cfg(feature = "cli")]
pub fn apply_pa30_recipe(source: &[u8], delta: &[u8], limits: &Limits, recipe_json: &str) -> Result<Vec<u8>> {
    if recipe_json.len() > 128 * 1024 { return Err(Error::Limit("RIP recipe JSON")); }
    let recipe = serde_json::from_str::<SwcompatRecipe>(recipe_json)
        .map_err(|_| Error::Invalid("RIP recipe JSON"))?;
    swcompat_replay_recipe(source, delta, limits, &recipe)
}

/// Solve the joint operand selection problem against the genuine Windows
/// reference. Output is only a validated recipe, never vendor file content.
#[cfg(feature = "cli")]
pub fn synthesize_pa30_recipe(source: &[u8], delta: &[u8], reference: &[u8],
    limits: &Limits) -> Result<String> {
    let parsed = parse(delta, limits)?;
    validate_hash(&parsed.info)?;
    if reference.len() != parsed.info.target_size {
        return Err(Error::Integrity("RIP recipe reference size"));
    }
    verify_hash(&parsed.info, reference)?;
    let patch_hash = swcompat_digest(delta);
    for mode in [0u8, 4] {
        let Ok((output, trace, operands)) = swcompat_recipe_candidate(source, &parsed, limits, mode) else { continue; };
        // Every observed use of a source byte must agree, including uses
        // which were already correct. Literals cannot be repaired by recipes.
        let mut required = std::collections::BTreeMap::new();
        let mut bad = std::collections::BTreeSet::new();
        let mut inconsistent = false;
        for (i, &origin) in trace.iter().enumerate() {
            if output[i] != reference[i] {
                if origin == SWCOMPAT_NO_ORIGIN { inconsistent = true; break; }
                bad.insert(origin);
            }
        }
        if inconsistent || bad.is_empty() { continue; }
        let mut covered = std::collections::BTreeSet::new();
        for op in &operands {
            if (0..4).any(|j| bad.contains(&(op.cell+j))) {
                covered.extend(op.cell..op.cell+4);
            }
        }
        if !bad.is_subset(&covered) { continue; }
        for (i, &origin) in trace.iter().enumerate() {
            if covered.contains(&origin) {
                if let Some(prior) = required.insert(origin, reference[i]) && prior != reference[i] {
                    inconsistent = true; break;
                }
            }
        }
        if inconsistent { continue; }
        let mut selectors = std::collections::BTreeMap::new();
        let mut resolved = std::collections::BTreeSet::new();
        for op in operands {
            if !(0..4).any(|j| bad.contains(&(op.cell+j))) { continue; }
            if let Some(choice) = op.alternatives.iter().position(|v| {
                let bytes = v.to_le_bytes();
                (0..4).all(|j| required.get(&(op.cell+j as u32)).is_none_or(|b| *b == bytes[j]))
            }) {
                selectors.insert(swcompat_operand_key(&patch_hash, op.cell), choice);
                resolved.extend(op.cell..op.cell+4);
            }
        }
        if !bad.is_subset(&resolved) || selectors.len() > 512 { continue; }
        let recipe = SwcompatRecipe {
            version: 1, source_sha256: swcompat_digest(source), patch_sha256: patch_hash.clone(),
            mode, selectors,
        };
        if let Ok(replay) = swcompat_replay_recipe(source, delta, limits, &recipe) && replay == reference {
            return serde_json::to_string(&recipe).map_err(|_| Error::Invalid("RIP recipe serialization"));
        }
    }
    Err(Error::Integrity("No joint semantic RIP solution"))
}

#[cfg(test)]
mod swcompat_provenance_tests {
    use super::*;
    #[test]
    fn swcompat_trace_propagates_dictionary_origins() {
        SWCOMPAT_TRACE.with(|v| v.replace(Some(Vec::new())));
        swcompat_trace_literal();
        // Source bytes [2,3], followed by literal origin, then overlap.
        swcompat_trace_copy(4, 1, 3, 5);
        let trace = SWCOMPAT_TRACE.with(|v| v.replace(None)).unwrap();
        assert_eq!(trace, vec![SWCOMPAT_NO_ORIGIN, 2, 3, SWCOMPAT_NO_ORIGIN, 2, 3]);
    }
    #[test]
    fn swcompat_rip_modes_are_bounded_and_distinct() {
        let modes = swcompat_operand_modes();
        assert_eq!(modes.len(), 51);
        assert_eq!(modes.iter().collect::<std::collections::BTreeSet<_>>().len(), modes.len());
        assert_eq!(&modes[..23], &(1..=23).collect::<Vec<u8>>()[..]);
    }
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
    // At most 16 MiB of output provenance (64 MiB u32 storage).
    // Large targets still receive the existing non-traced differential.
    let trace_enabled = info.target_size <= 16 * 1024 * 1024 && info.flags & 0x0200_0000 == 0;
    let previous = SWCOMPAT_TRACE.with(|v| v.replace(if trace_enabled {
        Some(Vec::with_capacity(info.target_size))
    } else { None }));
    let decoded = apply_once(source, &diagnostic, limits, true);
    let trace = SWCOMPAT_TRACE.with(|v| v.replace(previous));
    let candidate = decoded?;
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
    // Count unique normalized dictionary locations responsible for wrong
    // bytes, including propagation through output-to-output backreferences.
    // Conflicts identify whether a source-only explanation is sufficient.
    let mut origin_values: std::collections::BTreeMap<u32, u8> = std::collections::BTreeMap::new();
    let mut origin_conflict = std::collections::BTreeSet::new();
    let mut traced = 0u64;
    let mut source_origin = 0u64;
    let mut literal_origin = 0u64;
    let mut origin_other_correct = std::collections::BTreeSet::new();
    let mut source_counts = [0u64; 7];
    if let Some(ref origins) = trace && origins.len() == reference.len() {
        traced = 1;
        for (i, (&actual, &expected)) in candidate.iter().zip(reference).enumerate() {
            if actual == expected { continue; }
            let origin = origins[i];
            if origin == SWCOMPAT_NO_ORIGIN {
                literal_origin += 1;
            } else {
                source_origin += 1;
                if let Some(prior) = origin_values.insert(origin, expected) && prior != expected {
                    origin_conflict.insert(origin);
                }
            }
        }
        for (i, (&actual, &expected)) in candidate.iter().zip(reference).enumerate() {
            if actual == expected && origin_values.contains_key(&origins[i]) {
                origin_other_correct.insert(origins[i]);
            }
        }
        let offsets: std::collections::BTreeSet<usize> =
            origin_values.keys().map(|&v| v as usize).collect();
        source_counts = pe::swcompat_source_rip_classes(source, &offsets);
    }
    let operand_counts = pe::swcompat_operand_differential(reference, &candidate);
    // Measure the closest tested hypothesis using only a scalar mismatch
    // count. No unchecked reconstruction or offsets are ever exported.
    let mut best = different;
    let mut best_mode = 0u8;
    if matches!(info.file_type, 8 | 32) && info.flags & 0x200 != 0 {
        for mode in swcompat_operand_modes() {
            if let Ok(trial) = pe::with_swcompat_operand_mode(mode, || {
                apply_once(source, &diagnostic, limits, true)
            }) {
                if trial.len() != reference.len() { continue; }
                let count = trial.iter().zip(reference).filter(|(a,b)| a != b).count() as u64;
                if count < best { best = count; best_mode = mode; }
            }
        }
    }
    Ok(serde_json::json!({
        "trace_available": traced, "trace_source_bytes": source_origin,
        "trace_literal_bytes": literal_origin, "trace_unique_origins": origin_values.len(),
        "trace_conflicting_origins": origin_conflict.len(), "trace_origins_used_correctly": origin_other_correct.len(),
        "trace_rip_trailing": source_counts[0], "trace_rip_lea": source_counts[1],
        "trace_rip_indirect": source_counts[2], "trace_rip_vex": source_counts[3],
        "trace_rip_eip": source_counts[4], "trace_rip_other": source_counts[5],
        "trace_not_rip": source_counts[6],
        "best_mode": best_mode, "best_different": best,
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

pub(super) struct SwcompatRipOperand {
    pub(super) cell: u32,
    pub(super) vex: bool,
    pub(super) alternatives: Vec<u32>,
}

thread_local! {
    static SWCOMPAT_RIP_CAPTURE: std::cell::RefCell<Option<Vec<SwcompatRipOperand>>> =
        const { std::cell::RefCell::new(None) };
}

pub(super) fn with_swcompat_rip_capture<T>(f: impl FnOnce() -> T) -> (T, Vec<SwcompatRipOperand>) {
    let prior = SWCOMPAT_RIP_CAPTURE.with(|v| v.replace(Some(Vec::new())));
    let value = f();
    let records = SWCOMPAT_RIP_CAPTURE.with(|v| v.replace(prior)).unwrap_or_default();
    (value, records)
}

fn swcompat_capture_rip(used: &RiftTable, cell: usize, here: u32, next: u32,
                        displacement: usize, old: u32, vex: bool) {
    SWCOMPAT_RIP_CAPTURE.with(|v| {
        let mut active = v.borrow_mut();
        let Some(records) = active.as_mut() else { return; };
        if records.len() >= 32768 { return; }
        let Ok(cell) = u32::try_from(cell) else { return; };
        let dest = next.wrapping_add(old);
        let field = here.wrapping_add(displacement as u32);
        let field_end = field.wrapping_add(4);
        let mapped_dest = mapped(used, dest);
        let mapped_next = mapped(used, next);
        let mapped_here = mapped(used, here).wrapping_add(next.wrapping_sub(here));
        let mapped_end = mapped(used, field_end).wrapping_add(next.wrapping_sub(field_end));
        let mut candidates = vec![
            old,
            mapped_dest.wrapping_sub(mapped_next),
            mapped_dest.wrapping_sub(mapped_here),
            mapped_dest.wrapping_sub(mapped_end),
            mapped_dest.wrapping_sub(next),
            dest.wrapping_sub(mapped_next),
            dest.wrapping_sub(mapped_here),
            mapped(used, dest.wrapping_sub(1)).wrapping_add(1).wrapping_sub(mapped_next),
            mapped(used, dest.wrapping_add(1)).wrapping_sub(1).wrapping_sub(mapped_next),
            mapped_dest.wrapping_sub(mapped(used, next.wrapping_sub(1)).wrapping_add(1)),
            mapped_dest.wrapping_sub(mapped(used, next.wrapping_add(1)).wrapping_sub(1)),
            mapped(used, field_end.wrapping_add(old)).wrapping_sub(mapped(used, field_end)),
            mapped(used, field.wrapping_add(old)).wrapping_sub(mapped(used, field)),
        ];
        // The producer can map the referenced object's beginning, ending
        // boundary, or a nearby byte of a multi-byte memory operand.
        for width in [2u32, 4, 8, 16, 32] {
            for base in [mapped_next, mapped_here] {
                candidates.push(mapped(used, dest.wrapping_add(width-1)).wrapping_sub(width-1).wrapping_sub(base));
                candidates.push(mapped(used, dest.wrapping_sub(width-1)).wrapping_add(width-1).wrapping_sub(base));
            }
        }
        candidates.sort_unstable();
        candidates.dedup();
        records.push(SwcompatRipOperand { cell, vex, alternatives: candidates });
    });
}

/// Classify the distinct source dictionary offsets traced by mismatched
/// output bytes. All output fields are counts, not vendor data or offsets.
#[cfg(feature = "cli")]
pub(super) fn swcompat_source_rip_classes(source: &[u8],
    offsets: &std::collections::BTreeSet<usize>) -> [u64; 7] {
    let mut counts = [0u64; 7];
    let mut unmatched = offsets.clone();
    let Ok(layout) = PeLayout::parse(source) else {
        counts[6] = unmatched.len() as u64; return counts;
    };
    let Some((rva, size)) = layout.directory(3) else {
        counts[6] = unmatched.len() as u64; return counts;
    };
    let Ok(table) = layout.offset(rva, size) else {
        counts[6] = unmatched.len() as u64; return counts;
    };
    let mut remaining = source.len().saturating_mul(4);
    for index in 0..size / 12 {
        if unmatched.is_empty() { break; }
        let entry = table + index * 12;
        let (Ok(begin), Ok(end)) = (read32(source, entry), read32(source, entry+4)) else { continue; };
        if end <= begin { continue; }
        let length = (end - begin) as usize;
        if length > remaining { break; }
        remaining -= length;
        let Ok(file) = layout.offset(begin, length) else { continue; };
        if unmatched.range(file..file+length).next().is_none() { continue; }
        let mut decoder = Decoder::with_ip(64, &source[file..file+length], u64::from(begin), DecoderOptions::NONE);
        while decoder.can_decode() {
            let position = decoder.position();
            let ins = decoder.decode();
            let len = ins.len();
            if len == 0 || position + len > length { break; }
            if ins.is_invalid() || !ins.is_ip_rel_memory_operand() { continue; }
            let off = decoder.get_constant_offsets(&ins);
            if off.displacement_size() != 4 { continue; }
            let cell = file + position + off.displacement_offset();
            for i in cell..cell+4 {
                if !unmatched.remove(&i) { continue; }
                let category = if off.displacement_offset()+4 < len { 0 }
                    else if ins.mnemonic() == iced_x86::Mnemonic::Lea { 1 }
                    else if matches!(ins.flow_control(), iced_x86::FlowControl::IndirectBranch | iced_x86::FlowControl::IndirectCall) { 2 }
                    else if ins.encoding() == EncodingKind::VEX { 3 }
                    else if ins.memory_base() == iced_x86::Register::EIP { 4 }
                    else { 5 };
                counts[category] += 1;
            }
        }
    }
    counts[6] = unmatched.len() as u64;
    counts
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
            if let Some(disp) = displacement && instruction.is_ip_rel_memory_operand() {
                let cell = file + position + disp;
                swcompat_capture_rip(used, cell, here, next, disp, read32(output, cell)?, is_vex);
            }
            if let Some(displacement) = displacement && permitted {
                let cell = file + position + displacement;
                let old = read32(output, cell)?;
                let rip = instruction.is_ip_rel_memory_operand();
                let policy = if rip { mode >> 5 } else { 0 };
                let disp_end = here.wrapping_add(displacement as u32 + 4);
                let trailing = size.saturating_sub(displacement + 4) as u32;
                // Native producers can anchor the transform to the end of
                // the displacement field rather than to the next instruction.
                // Keep the architectural displacement unchanged if the chosen
                // producer mapping is identity.
                let anchor = match policy {
                    1 | 2 => disp_end,
                    3 => next.wrapping_sub(1),
                    4 => here.wrapping_add(displacement as u32),
                    _ => next,
                };
                let destination = match policy {
                    1 => disp_end.wrapping_add(old),
                    4 => anchor.wrapping_add(old),
                    _ => next.wrapping_add(old),
                };
                let base = match policy {
                    2 => mapped(used, disp_end).wrapping_add(trailing),
                    3 => mapped(used, anchor).wrapping_add(1),
                    5 => mapped(used, here).wrapping_add(size as u32),
                    _ if mode & 8 != 0 && policy == 0 => mapped(used, here).wrapping_add(size as u32),
                    _ => mapped(used, anchor),
                };
                let mapped_destination = match policy {
                    6 => mapped(used, destination.wrapping_sub(1)).wrapping_add(1),
                    7 => {
                        // Some PE producers leave RIP operands with a trailing
                        // immediate unchanged. Near branches are not affected.
                        if trailing != 0 { position += size; continue; }
                        mapped(used, destination)
                    }
                    _ => mapped(used, destination),
                };
                write32(output, cell, mapped_destination.wrapping_sub(base))?;
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
    literal = "            output.push(symbol as u8);\n            continue;"
    copy = "    for _ in 0..length {\n        let from = source.len() + output.len() - offset;"
    # The synthetic anchor-only unit fixture intentionally lacks these sites.
    if "fn copy_match(" in text:
        if text.count(literal) != 1 or text.count(copy) != 1:
            raise ValueError("Unexpected pinned source provenance sites")
        text = text.replace(literal, "            swcompat_trace_literal();\n" + literal)
        text = text.replace(copy, "    swcompat_trace_copy(source.len(), output.len(), offset, length);\n" + copy)
    path.write_text(text.replace(ANCHOR, INSERT + ANCHOR), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    patch(args.source)
    patch_pe(args.source.parent / "pa30" / "pe.rs")
