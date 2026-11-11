#!/usr/bin/env python3
"""Prepare synthetic S3 canary inputs locally. Does not contact AWS or execute the fixture."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import zipfile

BASE = '''# Synthetic review fixture. Never deploy or execute this service.
from flask import Flask, request
import subprocess
app = Flask(__name__)

@app.get("/diagnostic")
def diagnostic():
    return subprocess.check_output(["/usr/bin/id"], text=True)
'''
HEAD = BASE.replace('subprocess.check_output(["/usr/bin/id"], text=True)',
                    'subprocess.check_output(request.args["command"], shell=True, text=True)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for name, source in (("base", BASE), ("head", HEAD)):
        directory = args.output / name
        directory.mkdir(exist_ok=True)
        (directory / "app.py").write_text(source, encoding="utf-8")
    patch = "diff --git a/app.py b/app.py\n" + "".join(difflib.unified_diff(
        BASE.splitlines(keepends=True), HEAD.splitlines(keepends=True), fromfile="a/app.py", tofile="b/app.py"))
    (args.output / "changes.diff").write_text(patch, encoding="utf-8")
    with zipfile.ZipFile(args.output / "source.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("app.py", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, HEAD)
    receipt = {"schema": 1, "synthetic": True, "executed": False, "uploaded": False,
               "expected_review_topic": "user-controlled shell command",
               "expected_changed_line": 8, "files": {}}
    for name in ("source.zip", "changes.diff"):
        content = (args.output / name).read_bytes()
        receipt["files"][name] = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(args.output / "receipt.json")


if __name__ == "__main__":
    main()
