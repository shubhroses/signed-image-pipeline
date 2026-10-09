"""Decide which issues the rescan has to open.

The rescan asks Trivy about the SBOM of the latest release with the flags of
the scan gate. Its report therefore lists what the gate would fail on today:
High or Critical vulnerabilities that have a fix and that .trivyignore.yaml
does not accept. The image passed the gate when it was released, so each of
them is news: found, fixed, or no longer covered by an exception since then.

A vulnerability gets one issue, however many packages have it. It gets none
while an open issue names it in its title, so that a finding is reported once
and not again every week. Closing the issue while the finding is still there
brings it back at the next rescan.

This script decides and opens nothing. It prints one line of JSON for each
issue to open, with its title and its body, and says on standard error what it
decided about each vulnerability. Only the standard library is used, so that a
job can call this with the runner's own python3 and install nothing.

Usage: python3 scripts/rescan_issues.py REPORT OPEN_ISSUES IMAGE RUN_URL

REPORT is Trivy's report in JSON, OPEN_ISSUES is what
"gh issue list --state open --json title" printed, IMAGE is the release that
was rescanned and RUN_URL is where the run that rescanned it can be read.
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# What the gate fails on, worst first.
SEVERITIES = ("CRITICAL", "HIGH")

# What may stand next to an identifier in a title without being part of it.
PUNCTUATION = ".,:;()[]`'\""

# A title names this many packages and counts the rest.
PACKAGES_IN_TITLE = 3


@dataclass
class Finding:
    """One vulnerability, and every package of the image that has it."""

    identifier: str  # as Trivy prints it, such as a CVE or GHSA number
    severity: str  # the worst that Trivy gives it for any of the packages
    url: str  # where the advisory can be read; empty when Trivy has none
    packages: set[tuple[str, str, str]] = field(default_factory=set)  # name, installed, fixed


def findings(report: object) -> list[Finding]:
    """The vulnerabilities of a Trivy report, in the order of their identifiers.

    The report has to be one the gate's flags produced. A finding in it that
    has no fix, or that is less than High, shows that it is not, and reading
    on would open an issue for everything Trivy knows about the image.
    """
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise ValueError("the report is not a Trivy report in schema version 2")
    found: dict[str, Finding] = {}
    for result in report.get("Results") or []:
        for entry in result.get("Vulnerabilities") or []:
            identifier = entry["VulnerabilityID"]
            severity, status = entry.get("Severity"), entry.get("Status")
            if severity not in SEVERITIES or status != "fixed":
                raise ValueError(
                    f"{identifier} is {severity} with status {status}: "
                    "the report was not made with the flags of the scan gate"
                )
            finding = found.setdefault(
                identifier, Finding(identifier, severity, entry.get("PrimaryURL", ""))
            )
            if SEVERITIES.index(severity) < SEVERITIES.index(finding.severity):
                finding.severity = severity
            finding.packages.add(
                (entry["PkgName"], entry["InstalledVersion"], entry["FixedVersion"])
            )
    return [found[identifier] for identifier in sorted(found)]


def open_titles(issues: object) -> list[str]:
    """The titles in what "gh issue list --json title" printed."""
    if not isinstance(issues, list):
        raise ValueError("the open issues are not a list")
    return [issue["title"] for issue in issues]


def names(title: str, identifier: str) -> bool:
    """Whether the identifier is one of the words of an issue title.

    A whole word, so that an issue about CVE-2026-12345 is not taken for one
    about CVE-2026-1234. Capitals and the punctuation around the word do not
    count, so that an issue somebody wrote by hand is recognised too.
    """
    words = {word.strip(PUNCTUATION).casefold() for word in title.split()}
    return identifier.casefold() in words


def unreported(found: list[Finding], titles: list[str]) -> list[Finding]:
    """The findings that no open issue names."""
    return [
        finding
        for finding in found
        if not any(names(title, finding.identifier) for title in titles)
    ]


def issue_title(finding: Finding) -> str:
    """Starts with the identifier, which is what names() will look for."""
    packages = sorted({name for name, _, _ in finding.packages})
    listed = ", ".join(packages[:PACKAGES_IN_TITLE])
    if len(packages) > PACKAGES_IN_TITLE:
        listed += f" and {len(packages) - PACKAGES_IN_TITLE} more"
    return f"{finding.identifier}: {finding.severity} vulnerability with a fix in {listed}"


def issue_body(finding: Finding, image: str, run_url: str) -> str:
    """What was found, where, and what to do about it, in Markdown.

    Nothing of the advisory's own text is copied in: it was written by
    somebody else, and GitHub would act on a mention or a link inside it.
    """
    advisory = f"[{finding.identifier}]({finding.url})" if finding.url else finding.identifier
    rows = [
        f"| `{name}` | `{installed}` | `{fixed}` |"
        for name, installed, fixed in sorted(finding.packages)
    ]
    paragraphs = [
        f"The rescan of the latest release found {advisory}, which the scan gate would fail "
        f"on today: it is {finding.severity}, it has a fix, and `.trivyignore.yaml` does not "
        "accept it.",
        "\n".join(["| Package | Installed | Fixed in |", "|---|---|---|", *rows]),
        f"- Image: `{image}`\n- Found by: {run_url}",
        "The image passed the gate when it was released, so the vulnerability or its fix "
        "was published since then, or an exception for it has expired.",
        "To resolve this, release an image that has the fix, by updating the dependency or "
        "the base image digest. Dependabot may already propose that in a pull request. Or "
        "accept the finding in `.trivyignore.yaml`, with a reason and an expiry date. Then "
        "close this issue: the rescan does not close it, and opens a new one if it still "
        "finds the vulnerability and no open issue names it.",
    ]
    return "\n\n".join(paragraphs)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decide which issues the rescan has to open.")
    parser.add_argument("report", type=Path, help="Trivy's report in JSON")
    parser.add_argument("open_issues", type=Path, help="the open issues, as gh lists them")
    parser.add_argument("image", help="the release that was rescanned")
    parser.add_argument("run_url", help="where the run that rescanned it can be read")
    arguments = parser.parse_args(argv)

    try:
        found = findings(json.loads(arguments.report.read_text(encoding="utf-8")))
        titles = open_titles(json.loads(arguments.open_issues.read_text(encoding="utf-8")))
    except KeyError as error:
        print(f"rescan_issues: a finding or an issue has no {error}", file=sys.stderr)
        return 1
    except (TypeError, ValueError) as error:
        print(f"rescan_issues: {error}", file=sys.stderr)
        return 1

    new = unreported(found, titles)
    to_report = {finding.identifier for finding in new}
    for finding in found:
        decision = "has no open issue" if finding.identifier in to_report else "has an open issue"
        print(f"rescan_issues: {finding.identifier} {decision}", file=sys.stderr)
    print(f"rescan_issues: {len(found)} found, {len(new)} to report", file=sys.stderr)

    for finding in new:
        issue = {
            "title": issue_title(finding),
            "body": issue_body(finding, arguments.image, arguments.run_url),
        }
        print(json.dumps(issue))
    return 0


if __name__ == "__main__":
    sys.exit(main())
