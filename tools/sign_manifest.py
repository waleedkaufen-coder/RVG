#!/usr/bin/env python3
"""Sign an RVG update manifest (version.json) with Ed25519.

    keygen                         create a keypair; prints UPDATE_PUBLIC_KEY for the panel
    sign MANIFEST --key KEY_FILE   add sha256 + signature, write signed JSON

Manifest: {"version": "9.3", "description": "...",
           "files": [{"path": "main.py", "url": "https://.../main.py"}, ...]}
`sign --root DIR` fills each file's sha256 from DIR/<path>; entries that already
carry a sha256 are kept. Run it only on a trusted machine: the private key must
never reach the server. Signature scheme must match updater.verify_manifest_signature:
base64 Ed25519 over json.dumps(manifest minus "signature", sort_keys=True,
separators=(",", ":"), ensure_ascii=False) encoded as UTF-8.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical(manifest: dict) -> bytes:
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def cmd_keygen(args):
    out = Path(args.out)
    if out.exists():
        sys.exit(f"{out} already exists; refusing to overwrite")
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(S.Encoding.Raw, S.PrivateFormat.Raw, S.NoEncryption())
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.b64encode(raw).decode() + "\n")
    pub = key.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
    print(f"Private key written to {out} (keep it secret and off the server).")
    print("Set this on the panel:")
    print(f"UPDATE_PUBLIC_KEY={base64.b64encode(pub).decode()}")


def cmd_sign(args):
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        sys.exit("manifest has no files")
    for entry in files:
        if not entry.get("path") or not entry.get("url"):
            sys.exit(f"file entry needs path and url: {entry}")
        if not entry.get("sha256"):
            if not args.root:
                sys.exit(f"{entry['path']}: no sha256 and no --root to compute it from")
            data = (Path(args.root) / entry["path"].lstrip("/")).read_bytes()
            entry["sha256"] = hashlib.sha256(data).hexdigest()
        entry.pop("sha1", None)
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(args.key).read_text().strip()))
    manifest.pop("signature", None)
    manifest["signature"] = base64.b64encode(key.sign(canonical(manifest))).decode()
    out = Path(args.out or args.manifest)
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Signed manifest written to {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", default="rvg_update_private.key")
    k.set_defaults(fn=cmd_keygen)
    s = sub.add_parser("sign")
    s.add_argument("manifest")
    s.add_argument("--key", required=True)
    s.add_argument("--root", help="directory holding the release files, to compute sha256")
    s.add_argument("--out", help="output path (default: overwrite the manifest)")
    s.set_defaults(fn=cmd_sign)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
