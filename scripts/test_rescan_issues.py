import json

import pytest

from scripts.rescan_issues import (
    Finding,
    findings,
    issue_body,
    issue_title,
    main,
    names,
    open_titles,
    unreported,
)

IMAGE = "ghcr.io/example/app@sha256:" + "0" * 64
RUN_URL = "https://github.com/example/app/actions/runs/1"


def vulnerability(identifier: str, package: str, **changes: str) -> dict:
    """One finding, with the fields Trivy 0.75 writes that the script reads."""
    entry = {
        "VulnerabilityID": identifier,
        "PkgName": package,
        "InstalledVersion": "2.7.0",
        "FixedVersion": "2.8.0",
        "Status": "fixed",
        "Severity": "HIGH",
        "PrimaryURL": f"https://avd.aquasec.com/nvd/{identifier.lower()}",
        "Title": f"{package}: something an advisory says about @somebody",
    }
    return entry | changes


def report(*results: list[dict] | None) -> dict:
    """A Trivy report with one result for each list of findings given."""
    return {
        "SchemaVersion": 2,
        "ArtifactType": "spdx",
        "Results": [
            {"Target": f"target {number}", "Vulnerabilities": found}
            for number, found in enumerate(results)
        ],
    }


URLLIB3 = vulnerability("CVE-2026-97687", "urllib3")
MSGPACK = vulnerability(
    "GHSA-6v7p-g79w-8964", "msgpack", InstalledVersion="1.1.2", FixedVersion="1.2.1"
)


WITHOUT_A_PACKAGE = {"VulnerabilityID": "CVE-2026-2", "Severity": "HIGH", "Status": "fixed"}


# Reading the report


def test_a_report_without_findings_gives_none():
    # Trivy leaves "Vulnerabilities" out of a result that has none.
    clean = {"SchemaVersion": 2, "Results": [{"Target": "Python"}, {"Target": "debian"}]}

    assert findings(clean) == []
    assert findings(report(None, [])) == []
    assert findings({"SchemaVersion": 2}) == []


def test_each_vulnerability_is_one_finding():
    found = findings(report([URLLIB3, MSGPACK]))

    assert found == [
        Finding(
            "CVE-2026-97687",
            "HIGH",
            "https://avd.aquasec.com/nvd/cve-2026-97687",
            {("urllib3", "2.7.0", "2.8.0")},
        ),
        Finding(
            "GHSA-6v7p-g79w-8964",
            "HIGH",
            "https://avd.aquasec.com/nvd/ghsa-6v7p-g79w-8964",
            {("msgpack", "1.1.2", "1.2.1")},
        ),
    ]


def test_a_vulnerability_in_several_packages_is_still_one_finding():
    in_two_results = report(
        [vulnerability("CVE-2026-1", "libssl3t64"), vulnerability("CVE-2026-1", "openssl")],
        [vulnerability("CVE-2026-1", "openssl")],
    )

    (finding,) = findings(in_two_results)

    assert finding.packages == {("libssl3t64", "2.7.0", "2.8.0"), ("openssl", "2.7.0", "2.8.0")}


def test_findings_come_in_the_order_of_their_identifiers():
    found = findings(report([MSGPACK], [URLLIB3, vulnerability("CVE-2025-47273", "setuptools")]))

    assert [finding.identifier for finding in found] == [
        "CVE-2025-47273",
        "CVE-2026-97687",
        "GHSA-6v7p-g79w-8964",
    ]


@pytest.mark.parametrize("order", [("HIGH", "CRITICAL"), ("CRITICAL", "HIGH")])
def test_a_finding_has_the_worst_severity_of_its_packages(order):
    first, second = order
    mixed = report(
        [
            vulnerability("CVE-2026-1", "libc6", Severity=first),
            vulnerability("CVE-2026-1", "libc-bin", Severity=second),
        ]
    )

    assert findings(mixed)[0].severity == "CRITICAL"


def test_a_finding_without_an_advisory_address_is_read():
    without_url = dict(URLLIB3)
    del without_url["PrimaryURL"]

    assert findings(report([without_url]))[0].url == ""


@pytest.mark.parametrize(
    "changes",
    [
        {"Status": "affected"},
        {"Status": "will_not_fix"},
        {"Severity": "MEDIUM"},
        {"Severity": "UNKNOWN"},
    ],
)
def test_a_finding_the_gate_would_not_fail_on_shows_the_report_is_not_the_gates(changes):
    unfiltered = report([URLLIB3, vulnerability("CVE-2026-2", "libc6", **changes)])

    with pytest.raises(ValueError, match="CVE-2026-2 .* not made with the flags of the scan gate"):
        findings(unfiltered)


@pytest.mark.parametrize(
    "document",
    [
        {"spdxVersion": "SPDX-2.3", "packages": []},  # an SBOM
        {"SchemaVersion": 1, "Results": []},
        [],
        None,
    ],
)
def test_what_is_not_a_trivy_report_is_refused(document):
    with pytest.raises(ValueError, match="not a Trivy report"):
        findings(document)


# Whether an open issue names a finding


def test_the_titles_are_read_from_what_gh_prints():
    assert open_titles([{"title": "One"}, {"title": "Two"}]) == ["One", "Two"]
    assert open_titles([]) == []


def test_what_is_not_a_list_of_issues_is_refused():
    with pytest.raises(ValueError, match="not a list"):
        open_titles({"title": "One"})


@pytest.mark.parametrize(
    "title",
    [
        "CVE-2026-1234: HIGH vulnerability with a fix in urllib3",
        "Update urllib3 (CVE-2026-1234)",
        "cve-2026-1234 in the base image",
        "[CVE-2026-1234] urllib3",
        "Fix `CVE-2026-1234`.",
    ],
)
def test_a_title_with_the_identifier_as_a_word_names_the_finding(title):
    assert names(title, "CVE-2026-1234")


@pytest.mark.parametrize(
    "title",
    [
        "CVE-2026-12345: HIGH vulnerability with a fix in urllib3",
        "CVE-2026-123: HIGH vulnerability with a fix in urllib3",
        "XCVE-2026-1234",
        "Update urllib3",
        "",
    ],
)
def test_a_title_without_the_identifier_as_a_word_does_not(title):
    assert not names(title, "CVE-2026-1234")


def test_the_title_of_an_issue_names_its_finding():
    for finding in findings(report([URLLIB3, MSGPACK])):
        assert names(issue_title(finding), finding.identifier)


def test_only_findings_no_open_issue_names_are_unreported():
    found = findings(report([URLLIB3, MSGPACK]))
    titles = ["Something else", "CVE-2026-97687: HIGH vulnerability with a fix in urllib3"]

    assert [finding.identifier for finding in unreported(found, titles)] == ["GHSA-6v7p-g79w-8964"]
    assert unreported(found, []) == found
    assert unreported([], titles) == []


# What an issue says


def test_the_title_says_what_how_bad_and_where():
    (finding,) = findings(report([URLLIB3]))

    assert issue_title(finding) == "CVE-2026-97687: HIGH vulnerability with a fix in urllib3"


def test_the_title_names_three_packages_and_counts_the_rest():
    packages = ["libc6", "libc-bin", "libc-l10n", "locales", "nscd"]
    (finding,) = findings(report([vulnerability("CVE-2026-1", name) for name in packages]))

    assert issue_title(finding) == (
        "CVE-2026-1: HIGH vulnerability with a fix in libc-bin, libc-l10n, libc6 and 2 more"
    )


def test_the_body_says_what_was_found_where_and_by_which_run():
    (finding,) = findings(report([URLLIB3, vulnerability("CVE-2026-97687", "pip")]))

    body = issue_body(finding, IMAGE, RUN_URL)

    assert "[CVE-2026-97687](https://avd.aquasec.com/nvd/cve-2026-97687)" in body
    assert "it is HIGH" in body
    assert "| `pip` | `2.7.0` | `2.8.0` |\n| `urllib3` | `2.7.0` | `2.8.0` |" in body
    assert f"- Image: `{IMAGE}`" in body
    assert f"- Found by: {RUN_URL}" in body
    assert ".trivyignore.yaml" in body


def test_the_body_copies_nothing_of_the_advisorys_own_text():
    (finding,) = findings(report([URLLIB3]))

    assert "@somebody" not in issue_body(finding, IMAGE, RUN_URL)


def test_the_body_names_a_finding_without_an_advisory_address_plainly():
    finding = Finding("CVE-2026-1", "HIGH", "", {("libc6", "2.41-12", "2.41-13")})

    body = issue_body(finding, IMAGE, RUN_URL)

    assert "found CVE-2026-1, which" in body
    assert "](" not in body


# The command line


def run(tmp_path, document, issues) -> list[str]:
    """Write the two files and return the arguments of the command line."""
    report_path, issues_path = tmp_path / "rescan.json", tmp_path / "open-issues.json"
    report_path.write_text(json.dumps(document), encoding="utf-8")
    issues_path.write_text(json.dumps(issues), encoding="utf-8")
    return [str(report_path), str(issues_path), IMAGE, RUN_URL]


def test_the_command_line_prints_one_line_of_json_for_each_issue_to_open(tmp_path, capsys):
    reported = [{"title": "CVE-2026-97687: HIGH vulnerability with a fix in urllib3"}]

    assert main(run(tmp_path, report([URLLIB3, MSGPACK]), reported)) == 0

    captured = capsys.readouterr()
    (line,) = captured.out.splitlines()
    issue = json.loads(line)
    assert issue["title"] == "GHSA-6v7p-g79w-8964: HIGH vulnerability with a fix in msgpack"
    assert f"- Image: `{IMAGE}`" in issue["body"]
    assert "CVE-2026-97687 has an open issue" in captured.err
    assert "GHSA-6v7p-g79w-8964 has no open issue" in captured.err
    assert "2 found, 1 to report" in captured.err


def test_the_command_line_prints_nothing_when_nothing_was_found(tmp_path, capsys):
    assert main(run(tmp_path, report(None, None), [])) == 0

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "0 found, 0 to report" in captured.err


@pytest.mark.parametrize(
    ("document", "issues", "message"),
    [
        ({"spdxVersion": "SPDX-2.3"}, [], "not a Trivy report"),
        (report([vulnerability("CVE-2026-2", "libc6", Status="affected")]), [], "flags of the"),
        (report([WITHOUT_A_PACKAGE]), [], "has no 'PkgName'"),
        (report([URLLIB3]), {"message": "Bad credentials"}, "not a list"),
        (report([URLLIB3]), [{"number": 1}], "has no 'title'"),
    ],
)
def test_the_command_line_fails_and_opens_nothing_on_input_it_cannot_read(
    tmp_path, capsys, document, issues, message
):
    assert main(run(tmp_path, document, issues)) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert message in captured.err


def test_the_command_line_fails_on_a_report_that_is_not_json(tmp_path, capsys):
    arguments = run(tmp_path, report(), [])
    (tmp_path / "rescan.json").write_text("", encoding="utf-8")

    assert main(arguments) == 1
    assert capsys.readouterr().out == ""
