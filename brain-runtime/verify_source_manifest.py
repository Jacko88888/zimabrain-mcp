import hashlib
import json
import pathlib
import sys


def verify(source_root, manifest_path):
    root = pathlib.Path(source_root).resolve()
    manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
    files = manifest.get("files") or []
    if manifest.get("fileCount") != len(files):
        raise ValueError("source manifest fileCount does not match its file list")
    for item in files:
        relative = pathlib.PurePosixPath(item["path"])
        path = (root / relative).resolve()
        if root not in path.parents:
            raise ValueError(f"manifest path escapes source root: {relative}")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != item["size"]:
            raise ValueError(f"size mismatch: {relative}")
        if digest != item["sha256"]:
            raise ValueError(f"sha256 mismatch: {relative}")
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_source_manifest.py SOURCE_ROOT MANIFEST")
    verify(sys.argv[1], sys.argv[2])
