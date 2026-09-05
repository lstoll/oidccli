#!/usr/bin/env python3
"""Bump version and per-platform sha256 in homebrew-tap/Formula/oidccli.rb."""
import hashlib
import pathlib
import re
import sys

if len(sys.argv) != 2:
    raise SystemExit(f"usage: {sys.argv[0]} VERSION")

version = sys.argv[1]
path = pathlib.Path("homebrew-tap/Formula/oidccli.rb")
if not path.is_file():
    raise SystemExit(f"missing {path}; Formula/oidccli.rb must exist in lstoll/homebrew-tap")

text = path.read_text()
text, n1 = re.subn(r'version "[^"]+"', f'version "{version}"', text, count=1)
if n1 != 1:
    raise SystemExit(f"formula replace failed: version={n1}")

for key in ("darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64"):
    archive = pathlib.Path("dist") / f"oidccli-{version}-{key}.tar.gz"
    if not archive.is_file():
        raise SystemExit(f"missing {archive}")
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    text, n = re.subn(
        rf'(oidccli-#\{{version\}}-{re.escape(key)}\.tar\.gz"\n\s*sha256 )"[^"]+"',
        rf'\1"{sha}"',
        text,
        count=1,
    )
    if n != 1:
        raise SystemExit(f"formula replace failed: sha256 {key}={n}")

path.write_text(text)
