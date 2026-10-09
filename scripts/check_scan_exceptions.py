"""Check the scan exceptions in Trivy's YAML ignore file.

Trivy stops reporting any finding listed in that file. To Trivy the reason and
the expiry date of an entry are optional, and a key it does not know is skipped
without a word, so on its own it accepts an exception that nobody explained and
that never ends. This check makes the reason and the expiry mandatory, limits
how far ahead the expiry may be, and refuses anything Trivy would skip.

Usage: python scripts/check_scan_exceptions.py .trivyignore.yaml
"""

import argparse
import datetime
import sys
from pathlib import Path

import yaml

MAX_DAYS = 90

# Everything Trivy 0.75 reads from the file. A misspelt "expired_at" would make
# an exception permanent and a misspelt "purls" would widen it to every package,
# so a name that is not listed here is an error. Trivy still calls the format
# experimental: compare these names with its documentation when its pin moves.
SECTIONS = {"vulnerabilities", "misconfigurations", "secrets", "licenses"}
ENTRY_KEYS = {"id", "paths", "purls", "statement", "expired_at"}


def check(text: str, today: datetime.date) -> list[str]:
    """Return one line per problem. An empty list means the file is acceptable."""
    try:
        document = yaml.safe_load(text)
    except (yaml.YAMLError, ValueError) as error:  # ValueError: a date like 2026-02-30
        return [f"cannot be read: {error}"]

    if document is None:  # an empty file excepts nothing
        return []
    if not isinstance(document, dict):
        return ["must be a mapping of sections, such as 'vulnerabilities:'"]

    problems = []
    for section, entries in document.items():
        if section not in SECTIONS:
            problems.append(f"unknown section '{section}': Trivy would skip it")
            continue
        if entries is None:  # a section whose entries have all been removed
            continue
        if not isinstance(entries, list):
            problems.append(f"section '{section}' must be a list of exceptions")
            continue
        for number, entry in enumerate(entries, start=1):
            problems += check_entry(f"{section} entry {number}", entry, today)
    return problems


def check_entry(where: str, entry: object, today: datetime.date) -> list[str]:
    """Return the problems of one exception, each prefixed with where it is."""
    if not isinstance(entry, dict):
        return [f"{where}: must be a mapping with id, statement and expired_at"]

    problems = [
        f"unknown key '{key}': Trivy would skip it" for key in entry if key not in ENTRY_KEYS
    ]

    if is_text(entry.get("id")):
        where = f"{where} ({entry['id']})"
    else:
        problems.append("has no id")

    if not is_text(entry.get("statement")):
        problems.append("has no reason: write one in 'statement'")

    expires = entry.get("expired_at")
    latest = today + datetime.timedelta(days=MAX_DAYS)
    # Exactly a date, which is how YAML reads 2026-12-31. A quoted date is a
    # string, and a date with a time of day is a datetime (a subclass of date)
    # that would raise the question of whose midnight is meant.
    if type(expires) is not datetime.date:
        problems.append("has no usable expiry date: write 'expired_at' as a plain date, YYYY-MM-DD")
    elif expires <= today:
        # Trivy stops honouring an entry on its expired_at date, not the day after.
        problems.append(f"expired on {expires}: remove it, or review it and set a new date")
    elif expires > latest:
        problems.append(
            f"expires on {expires}, more than {MAX_DAYS} days away: "
            f"the latest date allowed today is {latest}"
        )

    return [f"{where}: {problem}" for problem in problems]


def is_text(value: object) -> bool:
    """True for a string that is more than whitespace."""
    return isinstance(value, str) and bool(value.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the exceptions in a Trivy ignore file.")
    parser.add_argument("file", type=Path, help="Trivy's YAML ignore file")
    path = parser.parse_args(argv).file

    # Trivy compares expired_at with the current time in UTC, so "today" is
    # the UTC date here too, on a laptop as much as on a runner.
    today = datetime.datetime.now(datetime.UTC).date()
    problems = check(path.read_text(encoding="utf-8"), today)

    for problem in problems:
        print(f"{path}: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"{path}: no exception is unexplained, expired or more than {MAX_DAYS} days from expiry")
    return 0


if __name__ == "__main__":
    sys.exit(main())
