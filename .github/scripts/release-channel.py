#!/usr/bin/env python3
"""Release channel rules for the image.

  classify TAG             print line, version, prerelease and v2 image tags
                           as key=value lines (for $GITHUB_OUTPUT)
  check-advance            fail if moving a channel tag from CURRENT (the
      --new V --current C  version label of the image it points at now) to
                           V would go to a lower version
  check-manifest FILE      validate a stable manifest whose signature was
      --version V          already verified; prints the digest
      --image IMAGE

Tags must be strict semver: v1.X.Y[-pre] or v2.X.Y[-pre]. v1 tags keep
their own job in release.yml. v2 releases get :<version>, :2 and :beta;
v2 pre-releases get :<version> and :beta. v2 never gets :latest or :1.*.
"""
import argparse
import datetime
import json
import re
import sys

SEMVER = (
    r"(?P<version>(?P<major>0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?P<pre>-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)"
)
TAG = re.compile(r"^v" + SEMVER + r"\Z")
LABEL = re.compile(r"^v?" + SEMVER + r"\Z")
STABLE_VERSION = re.compile(r"^2\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}\Z")
FORBIDDEN = re.compile(r"^(latest|1|1\..*)\Z")


class Error(Exception):
    pass


def classify(tag):
    m = TAG.match(tag)
    if not m or m.group("major") not in ("1", "2") or _leading_zero(m.group("pre")):
        raise Error(f"tag {tag!r} is not v1.X.Y[-pre] or v2.X.Y[-pre]")
    version, pre = m.group("version"), bool(m.group("pre"))
    if m.group("major") == "1":
        tags = []
    else:
        tags = [version, "beta"] if pre else [version, "2", "beta"]
    for t in tags:
        if FORBIDDEN.match(t):
            raise Error(f"refusing to publish v2 under :{t}")
    return {
        "line": "v" + m.group("major"),
        "version": version,
        "prerelease": "true" if pre else "false",
        "tags": " ".join(tags),
    }


def _leading_zero(pre):
    return any(i.isdigit() and len(i) > 1 and i[0] == "0" for i in (pre or "-")[1:].split("."))


def _key(version):
    m = LABEL.match(version or "")
    if not m or _leading_zero(m.group("pre")):
        raise Error(f"not a semver version: {version!r}")
    core, _, pre = m.group("version").partition("-")
    nums = tuple(int(x) for x in core.split("."))
    if not pre:
        return nums, (1,)
    ids = []
    for i in pre.split("."):
        ids.append((0, int(i), "") if i.isdigit() else (1, 0, i))
    return nums, (0, tuple(ids))


def check_advance(new, current):
    """Semver precedence; equal is allowed so a re-run is idempotent."""
    if _key(new) < _key(current):
        raise Error(f"refusing to move a channel from {current} back to {new}")


def check_manifest(data, version, image, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if not STABLE_VERSION.match(version):
        raise Error(f"stable needs a v2 release version without suffix, got {version!r}")
    want = {"channel", "image", "version", "digest", "expires"}
    if not isinstance(data, dict) or set(data) != want:
        raise Error(f"manifest must have exactly the keys {sorted(want)}")
    if data["channel"] != "stable":
        raise Error("manifest channel is not stable")
    if data["image"] != image:
        raise Error(f"manifest image {data['image']!r} is not {image!r}")
    if data["version"] != version:
        raise Error(f"manifest version {data['version']!r} is not {version!r}")
    if not isinstance(data["digest"], str) or not DIGEST.match(data["digest"]):
        raise Error("manifest digest is not a sha256 digest")
    try:
        expires = datetime.datetime.fromisoformat(data["expires"].replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise Error("manifest expires is not an RFC 3339 time")
    if expires.tzinfo is None:
        raise Error("manifest expires needs a time zone")
    if expires <= now:
        raise Error("manifest has expired")
    return data["digest"]


def main(argv):
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("classify")
    c.add_argument("tag")
    a = sub.add_parser("check-advance")
    a.add_argument("--new", required=True)
    a.add_argument("--current", required=True)
    m = sub.add_parser("check-manifest")
    m.add_argument("file")
    m.add_argument("--version", required=True)
    m.add_argument("--image", required=True)
    args = p.parse_args(argv)
    try:
        if args.cmd == "classify":
            for k, v in classify(args.tag).items():
                print(f"{k}={v}")
        elif args.cmd == "check-advance":
            check_advance(args.new, args.current)
        else:
            with open(args.file) as f:
                data = json.load(f)
            print(check_manifest(data, args.version, args.image))
    except (Error, json.JSONDecodeError, OSError) as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
