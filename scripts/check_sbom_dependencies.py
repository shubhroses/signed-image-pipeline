"""Check that an SBOM lists every direct dependency at its locked version.

requirements.in names the packages the app asks for and requirements.txt pins
the version of each that the image is built with. An SBOM made from that image
must therefore list each of them at exactly that version. If one is missing or
has another version, the SBOM describes some other build, or the scanner did
not see what was installed.

Only the direct dependencies are asked about: they are the ones somebody
chose, and they are always installed, which a pinned dependency of a
dependency need not be on every platform.

Each dependency that is listed as locked is printed as "name version", one to
a line, so that a caller can record what was found. Only the standard library
is used, so that a job can call this with the runner's own python3 and install
nothing.

Usage: python3 scripts/check_sbom_dependencies.py REQUIREMENTS_IN REQUIREMENTS_TXT SBOM
"""

import argparse
import json
import re
import sys
from pathlib import Path

# The start of a requirement line: a package name, then anything.
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
# A line of the lock, as pip-compile writes it: name==version.
PIN = re.compile(rf"({NAME.pattern})==([^\s\\;]+)")
# How an SPDX document names a package from PyPI: pkg:pypi/name@version, and
# then perhaps qualifiers after a "?".
PURL = re.compile(r"pkg:pypi/([^@?#]+)@([^?#]+)")


def normalise(name: str) -> str:
    """Python treats Typing_Extensions and typing-extensions as one name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def direct_dependencies(requirements_in: str) -> list[str]:
    """The package names in a requirements.in, without options and comments."""
    names = []
    for line in requirements_in.splitlines():
        line = line.split("#")[0].strip()
        match = NAME.match(line)  # an option such as "-c other.txt" does not match
        if match:
            names.append(normalise(match.group()))
    return names


def locked_versions(requirements_txt: str) -> dict[str, str]:
    """The version of every package pinned in a lock, by package name."""
    versions = {}
    for line in requirements_txt.splitlines():
        match = PIN.match(line)
        if match:
            versions[normalise(match.group(1))] = match.group(2)
    return versions


def sbom_versions(sbom: dict) -> dict[str, set[str]]:
    """The versions of every PyPI package an SPDX document lists, by package name."""
    versions: dict[str, set[str]] = {}
    for package in sbom.get("packages") or []:
        for reference in package.get("externalRefs") or []:  # absent for the base system
            match = PURL.match(reference.get("referenceLocator", ""))
            if match:
                versions.setdefault(normalise(match.group(1)), set()).add(match.group(2))
    return versions


def check(requirements_in: str, requirements_txt: str, sbom: dict) -> tuple[list[str], list[str]]:
    """Return what was found and what is wrong, one line each.

    Nothing wrong and nothing found cannot happen: a requirements.in that
    names no package is itself reported, so that an empty or misread file
    does not pass for want of anything to look for.
    """
    locked = locked_versions(requirements_txt)
    listed = sbom_versions(sbom)
    found, problems = [], []

    names = direct_dependencies(requirements_in)
    if not names:
        problems.append("requirements.in names no dependency, so there is nothing to look for")

    for name in names:
        if name not in locked:
            problems.append(f"{name} is not pinned in the lock")
        elif locked[name] in listed.get(name, set()):
            found.append(f"{name} {locked[name]}")
        elif name in listed:
            others = ", ".join(sorted(listed[name]))
            problems.append(f"{name} is locked at {locked[name]}, but the SBOM lists {others}")
        else:
            problems.append(f"{name} {locked[name]} is not in the SBOM")
    return found, problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check that an SBOM lists the locked direct dependencies."
    )
    parser.add_argument("requirements_in", type=Path, help="the direct dependencies")
    parser.add_argument("requirements_txt", type=Path, help="the lock made from them")
    parser.add_argument("sbom", type=Path, help="an SPDX document in JSON")
    paths = parser.parse_args(argv)

    try:
        sbom = json.loads(paths.sbom.read_text(encoding="utf-8"))
    except ValueError as error:
        print(f"{paths.sbom}: cannot be read as JSON: {error}", file=sys.stderr)
        return 1
    if not isinstance(sbom, dict):
        print(f"{paths.sbom}: is not an SPDX document", file=sys.stderr)
        return 1

    found, problems = check(
        paths.requirements_in.read_text(encoding="utf-8"),
        paths.requirements_txt.read_text(encoding="utf-8"),
        sbom,
    )
    for line in found:
        print(line)
    for problem in problems:
        print(f"{paths.sbom}: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
