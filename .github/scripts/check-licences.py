#!/usr/bin/env python3
"""Fail if a Go module dependency has a licence outside the allow-list.

Input: `go list -m -json all` on stdin (modules must be downloaded).
Policy: .github/licences.json. Anything outside "allowed" needs a
"decision" entry: {"module": ..., "license": ..., "reason": ...}.
"""
import json
import pathlib
import re
import sys

SIGNATURES = (
    ("AGPL-3.0", ("gnu affero general public license",)),
    ("SSPL-1.0", ("server side public license",)),
    ("LGPL", ("gnu lesser general public license",)),
    ("GPL", ("gnu general public license",)),
    ("MPL-2.0", ("mozilla public license", "2.0")),
    ("Apache-2.0", ("apache license", "version 2.0")),
    ("MIT", ("permission is hereby granted, free of charge",)),
    ("ISC", ("permission to use, copy, modify, and/or distribute this software for any purpose",)),
    ("BSD-3-Clause", ("redistribution and use in source and binary forms", "neither the name")),
    ("BSD-3-Clause", ("redistribution and use in source and binary forms", "names of its contributors")),
    ("BSD-2-Clause", ("redistribution and use in source and binary forms",)),
)
LICENCE_FILE = re.compile(r"^(licen[cs]e|copying)(\.(md|txt))?$", re.I)


def classify(text):
    t = " ".join(text.lower().split())
    for spdx, needles in SIGNATURES:
        if all(n in t for n in needles):
            return spdx
    return None


def licence_of(directory):
    files = sorted(p for p in pathlib.Path(directory).iterdir() if LICENCE_FILE.match(p.name))
    for f in files:
        spdx = classify(f.read_text(encoding="utf-8", errors="replace"))
        if spdx:
            return spdx
    return None


def modules(stream):
    decoder, text, pos = json.JSONDecoder(), stream.read(), 0
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            return
        obj, pos = decoder.raw_decode(text, pos)
        yield obj


def check(policy, mods):
    allowed = set(policy["allowed"])
    decided = {(d["module"], d["license"]) for d in policy.get("decision", [])}
    errors = []
    for m in mods:
        if m.get("Main"):
            continue
        path = m.get("Path")
        if not m.get("Dir"):
            errors.append(f"{path}: not downloaded; run go mod download first")
            continue
        spdx = licence_of(m["Dir"]) or "unknown"
        if spdx not in allowed and (path, spdx) not in decided:
            errors.append(f"{path}@{m.get('Version')}: licence {spdx} is not allowed and has no decision")
    return errors


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    policy = json.loads((root / "licences.json").read_text(encoding="utf-8"))
    mods = list(modules(sys.stdin))
    errors = check(policy, mods)
    for e in errors:
        print(f"::error::{e}")
    if errors:
        sys.exit(1)
    print(f"licences OK: {sum(1 for m in mods if not m.get('Main'))} modules")


if __name__ == "__main__":
    main()
