"""Check reviewed source paths, links and evidence; no third-party dependencies."""
from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {"README.md", "VERIFICATION.md", "pyproject.toml",
              ".gitignore", ".gitattributes"}
SOURCE_DIRS = {".github", "beaconlab", "configs", "docs", "examples", "scripts", "tests"}
TRANSIENT = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
             ".venv", "venv", "build", "dist", "runs", "htmlcov", ".idea", ".vscode"}
BLOCKED_SUFFIXES = {".pyc", ".pyo", ".key", ".pem", ".p12", ".pfx", ".pcap", ".pcapng", ".log", ".zip"}


def source_paths(root: Path = ROOT) -> list[Path]:
    if (root / ".git").exists():
        result = subprocess.run(["git", "ls-files", "-z", "--cached"], cwd=root,
                                check=True, capture_output=True)
        paths = [root / name.decode("utf-8") for name in result.stdout.split(b"\0") if name]
        if not paths:
            raise ValueError("No staged/tracked files; run git add . before checking a new repository")
        return sorted(set(paths))
    # Source archives have no Git index. Only ship the documented source roots.
    return sorted(p for p in root.rglob("*") if p.is_file()
                  and (p.relative_to(root).parts[0] in SOURCE_DIRS or p.name in ROOT_FILES)
                  and not any(part in TRANSIENT or part.endswith(".egg-info")
                              or part.startswith("local-tls-") for part in p.relative_to(root).parts)
                  and p.name != "RELEASE_SHA256.json")


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.targets = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "a" and "href" in values:
            self.targets.append(values["href"])
        if tag == "img" and "src" in values:
            self.targets.append(values["src"])


def check(root: Path = ROOT) -> tuple[list[Path], list[str]]:
    paths = source_paths(root)
    selected = {path.resolve() for path in paths}
    problems = []
    for path in paths:
        relative = path.relative_to(root)
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            problems.append(f"{relative}: missing file or unsupported symlink")
            continue
        if (relative.parts[0] not in SOURCE_DIRS and str(relative) not in ROOT_FILES
                or any(part in TRANSIENT or part.endswith(".egg-info") or part.startswith("local-tls-")
                       for part in relative.parts)
                or path.suffix in BLOCKED_SUFFIXES or path.name.startswith(".env")
                or path.name in {".DS_Store", "Thumbs.db", ".coverage", "RELEASE_SHA256.json"}):
            problems.append(f"{relative}: unexpected source or local artifact")
        data = path.read_bytes()
        if re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", data):
            problems.append(f"{relative}: private-key material")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            if path.suffix != ".png":
                problems.append(f"{relative}: unreviewed binary file type")
            continue
        if re.search(r"/(?:workspace|home|root|Users)/|\b[A-Za-z]:[\\/](?:Users|workspace)[\\/]", text):
            problems.append(f"{relative}: machine-specific local path")
        if re.search(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bAKIA[A-Z0-9]{16}\b", text):
            problems.append(f"{relative}: possible credential token")
        targets = []
        if path.suffix == ".md":
            targets = re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", text)
        elif path.suffix == ".html":
            parser = Links()
            parser.feed(text)
            targets = parser.targets
        for target in targets:
            url = urlsplit(target)
            if url.scheme or url.netloc or not url.path:
                continue
            destination = (path.parent / unquote(url.path)).resolve()
            if destination not in selected and not (destination.is_dir() and any(
                    p.is_relative_to(destination) for p in selected)):
                problems.append(f"{relative}: missing/untracked link {target}")

    for manifest_path in sorted((root / "examples").glob("*/manifest.json")):
        manifest = json.loads(manifest_path.read_text())
        folder = manifest_path.parent
        checks = {"model.json": manifest.get("model_sha256"), "plan.json": manifest.get("plan_sha256"),
                  "protocol.md": manifest.get("protocol_sha256")}
        for name, digest in checks.items():
            if digest and hashlib.sha256((folder / name).read_bytes()).hexdigest() != digest:
                problems.append(f"{folder.name}/{name}: recorded hash mismatch")
        # Code hashes identify the collection version, not necessarily today's
        # checkout. Historical evidence must survive future source improvements.
        recorded_sources = dict(manifest.get("analysis_source_sha256", {}))
        if manifest.get("generator_sha256"):
            recorded_sources["traffic.py"] = manifest["generator_sha256"]
        if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in recorded_sources.values()):
            problems.append(f"{folder.name}: invalid recorded source digest")
    for audit_path in sorted((root / "examples").glob("*/audit.json")):
        audit = json.loads(audit_path.read_text())
        for name, digest in audit["source_sha256"].items():
            source = root / "examples" / audit["source_experiment"] / name
            if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
                problems.append(f"{audit_path.parent.name}: audited source changed: {name}")
    return paths, problems


def main() -> int:
    try:
        paths, problems = check()
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Repository check failed: {exc}", file=sys.stderr)
        return 1
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"Repository checks passed: {len(paths)} reviewed source files; links, artifact hygiene and evidence hashes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
