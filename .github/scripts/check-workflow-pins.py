#!/usr/bin/env python3
"""Fail if a workflow uses an action not pinned to a full commit SHA, or lacks top-level permissions.

Reusable workflows triggered only by workflow_call are exempt from the top-level
permissions rule: they run with the permissions granted by the calling job.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
USES = re.compile(r"""^\s*(?:-\s+)?uses:\s*['"]?([^'"\s#]+)['"]?\s*(#.*)?$""")
SHA_REF = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
DIGEST_REF = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")

errors = []


def triggers(text):
    m = re.search(r"^on:[ \t]*(.*)$", text, re.M)
    if not m:
        return set()
    inline = m.group(1).split("#")[0].strip()
    if inline:
        return set(re.findall(r"[\w-]+", inline))
    keys = set()
    for line in text[m.end():].splitlines()[1:]:
        if line.strip() == "" or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            break
        k = re.match(r"^  ([\w-]+):", line)
        if k:
            keys.add(k.group(1))
    return keys


def check_uses(path, lineno, ref, comment):
    if ref.startswith("./"):
        return
    if ref.startswith("docker://"):
        if not DIGEST_REF.match(ref):
            errors.append(f"{path}:{lineno}: docker image not pinned by digest: {ref}")
        return
    if not SHA_REF.match(ref):
        errors.append(f"{path}:{lineno}: action not pinned to a commit SHA: {ref}")
    elif not comment:
        errors.append(f"{path}:{lineno}: pinned action missing version comment: {ref}")


def scan(path, is_workflow):
    text = path.read_text()
    rel = path.relative_to(ROOT)
    for i, line in enumerate(text.splitlines(), 1):
        m = USES.match(line)
        if m:
            check_uses(rel, i, m.group(1), m.group(2))
    if (
        is_workflow
        and not re.search(r"^permissions:", text, re.M)
        and triggers(text) != {"workflow_call"}
    ):
        errors.append(f"{rel}: missing top-level permissions")


gh = ROOT / ".github"
for p in sorted((gh / "workflows").glob("*.y*ml")):
    scan(p, True)
for p in sorted((gh / "actions").glob("**/action.y*ml")):
    scan(p, False)

for e in errors:
    print(e)
if errors:
    sys.exit(1)
print("workflow pins and permissions OK")
