"""Associate native Microsoft .NET setup BlockIf messages with their verdicts.

Microsoft's bootstrapper can print a human-readable blocker *before*
evaluating its condition. A string such as 'the OS is unsupported' followed
by 'BlockIf evaluated to false' is not evidence of an OS failure.

This private parser returns diagnostic message strings for local
classification only. Callers must never serialize descriptions, raw log
lines, filenames, Windows paths or original vendor content.
"""
from __future__ import annotations

import re

MAX_LINES = 30000
MAX_LINE = 8192
MAX_DESCRIPTION = 1536
MAX_BLOCK_LINES = 320

BLOCK = re.compile(r"\bBlockIf\s*:\s*(\S.*?)\s*$", re.IGNORECASE)
BEGIN = re.compile(r"\bevaluating\s+BlockIf\s*:", re.IGNORECASE)
RESULT = re.compile(r"\bBlockIf\s+evaluated\s+to\s+(true|false)\b",
                    re.IGNORECASE)


def extract(lines: list[str]) -> tuple[bool, list[str], list[str]]:
    """Return (any completed evaluation, true descriptions, unrelated lines).

    When structured verdicts exist, ignore all preliminary BlockIf text,
    including duplicate or multiline descriptions for FALSE conditions.
    Never infer TRUE from a condition's wording alone.
    """
    active = False
    evaluating = False
    current = ""
    seen = False
    true_descriptions: list[str] = []
    outer: list[str] = []
    block_lines = 0
    for line in lines[:MAX_LINES]:
        if len(line) > MAX_LINE:
            continue
        opening = BLOCK.search(line)
        if opening and not BEGIN.search(line):
            active = True
            evaluating = False
            current = opening.group(1)[:MAX_DESCRIPTION]
            block_lines = 0
            continue
        if active:
            block_lines += 1
            verdict = RESULT.search(line)
            if verdict:
                seen = True
                if verdict.group(1).casefold() == "true":
                    true_descriptions.append(current)
                active = False
                evaluating = False
                continue
            if BEGIN.search(line):
                evaluating = True
            elif not evaluating and block_lines < 8 and len(current) < MAX_DESCRIPTION:
                # Microsoft can break a BlockIf description across several
                # timestamp-prefixed lines. Keep the first description and
                # short continuations only, never its expression evaluation.
                continuation = re.sub(
                    r"^\s*\[[0-9/:, .-]{8,50}\]\s*", "", line).strip()
                if (continuation and not continuation.startswith((
                        "Operation", "RegKeyValue:", "Exists:", "And:",
                        "Or:", "Equals:", "Not:"))):
                    current = (current + " " + continuation)[:MAX_DESCRIPTION]
            if block_lines >= MAX_BLOCK_LINES:
                # Incomplete block: do not claim its content caused failure.
                active = False
                evaluating = False
            continue
        outer.append(line)
    return seen, true_descriptions, outer
