#!/usr/bin/env python3
"""Fail if a Go module dependency has a licence outside the allow-list.

Input: `go list -m -json all` on stdin (modules must be downloaded), or
`--npm <package-lock.json>` for an installed npm tool (`npm ci` first).
Packages are classified by their licence file, not by declared metadata.
Policy: .github/licences.json. Anything outside "allowed" needs a
"decision" entry: {"module": ..., "license": ..., "reason": ...}.
"""
import json
import pathlib
import re
import sys

# Copyleft is checked first, so a GPL-family file that mentions another
# licence is never let through as that licence. MPL 2.0 defines "Secondary
# License" by naming the GPL family; that one clause is dropped before
# matching, and only in a file that is itself MPL 2.0.
SIGNATURES = (
    ("AGPL-3.0", ("gnu affero general public license",)),
    ("SSPL-1.0", ("server side public license",)),
    ("LGPL", ("gnu lesser general public license",)),
    ("GPL", ("gnu general public license",)),
    ("MPL-2.0", ("mozilla public license", "version 2.0")),
    ("Apache-2.0", ("apache license", "version 2.0")),
    ("MIT", ("permission is hereby granted, free of charge",)),
    ("ISC", ("permission to use, copy, modify, and/or distribute this software for any purpose",)),
    ("BSD-3-Clause", ("redistribution and use in source and binary forms", "neither the name")),
    ("BSD-3-Clause", ("redistribution and use in source and binary forms", "names of its contributors")),
    ("BSD-2-Clause", ("redistribution and use in source and binary forms",)),
)
MPL_PREAMBLE = re.compile(r"^\W*mozilla public license,? version 2\.0\b")
MPL_SECONDARY = re.compile(r"\W*secondary license\W* means either the gnu general public license.*?versions of those licenses\.")
LICENCE_FILE = re.compile(r"^(licen[cs]e|copying)(\.(md|txt))?$", re.I)


def classify(text):
    t = " ".join(text.lower().split())
    if MPL_PREAMBLE.match(t):
        t = MPL_SECONDARY.sub(" ", t, count=1)
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


def npm_modules(lock_path):
    lock_path = pathlib.Path(lock_path)
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    for key, meta in lock.get("packages", {}).items():
        if not key:
            continue
        name = key.rsplit("node_modules/", 1)[-1]
        d = lock_path.parent / key
        yield {"Path": name, "Version": meta.get("version"), "Dir": str(d) if d.is_dir() else ""}


def check(policy, mods):
    allowed = set(policy["allowed"])
    decided = {(d["module"], d["license"]) for d in policy.get("decision", [])}
    errors = []
    for m in mods:
        if m.get("Main"):
            continue
        path = m.get("Path")
        if not m.get("Dir"):
            errors.append(f"{path}: not downloaded; run go mod download or npm ci first")
            continue
        spdx = licence_of(m["Dir"]) or "unknown"
        if spdx not in allowed and (path, spdx) not in decided:
            errors.append(f"{path}@{m.get('Version')}: licence {spdx} is not allowed and has no decision")
    return errors


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    policy = json.loads((root / "licences.json").read_text(encoding="utf-8"))
    if len(sys.argv) == 3 and sys.argv[1] == "--npm":
        mods = list(npm_modules(sys.argv[2]))
    else:
        mods = list(modules(sys.stdin))
    errors = check(policy, mods)
    for e in errors:
        print(f"::error::{e}")
    if errors:
        sys.exit(1)
    print(f"licences OK: {sum(1 for m in mods if not m.get('Main'))} packages")


if __name__ == "__main__":
    main()
