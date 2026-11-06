#!/usr/bin/env python3
"""Synchronize Kubit's release version across packaging and deployment files."""

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def source_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', text, re.MULTILINE)
    if not match:
        raise SystemExit("pyproject.toml does not contain exactly one project version")
    return match.group(1)


def expected_fragments(version: str) -> dict[str, tuple[str, ...]]:
    return {
        "pyproject.toml": (f'version = "{version}"',),
        "charts/kubit/Chart.yaml": (f"version: {version}", f'appVersion: "{version}"'),
        "base/deployment.yaml": (f"image: ghcr.io/lcontreras48/kubit:{version}",),
        "base/README.md": (f"?ref=v{version}", f"newTag: {version}"),
        "README.md": (f"source version is `{version}`", f"ghcr.io/lcontreras48/kubit:{version}"),
    }


def check(version: str) -> None:
    errors = []
    for relative_path, fragments in expected_fragments(version).items():
        text = (ROOT / relative_path).read_text(encoding="utf-8")
        for fragment in fragments:
            if fragment not in text:
                errors.append(f"{relative_path}: missing {fragment!r}")
    if errors:
        raise SystemExit("release versions are not aligned:\n" + "\n".join(errors))


def replace_once(relative_path: str, old: str, new: str) -> None:
    path = ROOT / relative_path
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"{relative_path}: expected exactly one occurrence of {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def update(current: str, target: str) -> None:
    replace_once("pyproject.toml", f'version = "{current}"', f'version = "{target}"')
    replace_once("charts/kubit/Chart.yaml", f"version: {current}", f"version: {target}")
    replace_once(
        "charts/kubit/Chart.yaml",
        f'appVersion: "{current}"',
        f'appVersion: "{target}"',
    )
    replace_once(
        "base/deployment.yaml",
        f"image: ghcr.io/lcontreras48/kubit:{current}",
        f"image: ghcr.io/lcontreras48/kubit:{target}",
    )
    replace_once("base/README.md", f"?ref=v{current}", f"?ref=v{target}")
    replace_once("base/README.md", f"newTag: {current}", f"newTag: {target}")
    replace_once(
        "README.md",
        f"source version is `{current}`",
        f"source version is `{target}`",
    )
    replace_once(
        "README.md",
        f"ghcr.io/lcontreras48/kubit:{current}",
        f"ghcr.io/lcontreras48/kubit:{target}",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", nargs="?", help="new MAJOR.MINOR.PATCH version")
    parser.add_argument("--check", action="store_true", help="only verify version alignment")
    args = parser.parse_args()
    if args.check and args.version:
        parser.error("version and --check are mutually exclusive")

    current = source_version()
    if args.check:
        check(current)
        print(f"release versions aligned: {current}")
        return
    if not args.version:
        parser.error("provide a version or --check")
    if not VERSION_PATTERN.fullmatch(args.version):
        parser.error("version must use MAJOR.MINOR.PATCH")
    if args.version != current:
        update(current, args.version)
    check(args.version)
    print(f"release version set to {args.version}")


if __name__ == "__main__":
    main()

