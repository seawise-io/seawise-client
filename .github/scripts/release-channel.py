#!/usr/bin/env python3
"""Release channel rules for the image.

  classify TAG             print line, version, prerelease and image tags
                           as key=value lines (for $GITHUB_OUTPUT)
  check-manifest FILE      validate a stable manifest whose signature was
      --version V          already verified; prints the digest
      --image IMAGE

v1 tags keep their own job in release.yml; this script only names the line
for them. v2 tags get :<version>, :2 and :beta, never :latest or :1.*.
"""
import argparse
import datetime
import json
import re
import sys

V1 = re.compile(r"^v1\.")
V2 = re.compile(
    r"^v(?P<version>2\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?P<pre>-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?)\Z"
)
STABLE_VERSION = re.compile(r"^2\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}\Z")
FORBIDDEN = re.compile(r"^(latest|1|1\..*)\Z")


class Error(Exception):
    pass


def classify(tag):
    if V1.match(tag):
        return {"line": "v1", "version": "", "prerelease": "false", "tags": ""}
    m = V2.match(tag)
    if not m:
        raise Error(f"tag {tag!r} is neither v1.* nor v2.X.Y[-pre]")
    version = m.group("version")
    tags = [version, "2", "beta"]
    for t in tags:
        if FORBIDDEN.match(t):
            raise Error(f"refusing to publish v2 under :{t}")
    return {
        "line": "v2",
        "version": version,
        "prerelease": "true" if m.group("pre") else "false",
        "tags": " ".join(tags),
    }


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
    m = sub.add_parser("check-manifest")
    m.add_argument("file")
    m.add_argument("--version", required=True)
    m.add_argument("--image", required=True)
    args = p.parse_args(argv)
    try:
        if args.cmd == "classify":
            for k, v in classify(args.tag).items():
                print(f"{k}={v}")
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
