import datetime

import pytest

from scripts.check_scan_exceptions import MAX_DAYS, check, main

# A fixed "today", so that only the two command-line tests depend on the clock.
TODAY = datetime.date(2026, 10, 8)
REASON = "The service never calls the affected function."
ENTRY = "vulnerabilities entry 1 (CVE-2099-0001)"


def in_days(days: int) -> datetime.date:
    return TODAY + datetime.timedelta(days=days)


def one_exception(statement=REASON, expired_at="2026-11-07"):
    """The text of an ignore file holding one exception. None leaves a key out."""
    lines = ["vulnerabilities:", "  - id: CVE-2099-0001"]
    if statement is not None:
        lines.append(f"    statement: {statement}")
    if expired_at is not None:
        lines.append(f"    expired_at: {expired_at}")
    return "\n".join(lines) + "\n"


# Valid entries


def test_an_entry_with_a_reason_and_an_expiry_within_the_limit_passes():
    assert check(one_exception(), TODAY) == []


def test_an_entry_may_expire_as_soon_as_tomorrow():
    assert check(one_exception(expired_at=in_days(1)), TODAY) == []


def test_an_entry_may_expire_exactly_on_the_limit():
    assert check(one_exception(expired_at=in_days(MAX_DAYS)), TODAY) == []


def test_an_entry_may_be_narrowed_to_paths_and_packages():
    text = one_exception() + "    paths: [deps/example]\n    purls: [pkg:pypi/example@1.0]\n"

    assert check(text, TODAY) == []


@pytest.mark.parametrize(
    "text", ["", "# a comment\n", "vulnerabilities:\n", "vulnerabilities: []\n"]
)
def test_a_file_without_exceptions_passes(text):
    assert check(text, TODAY) == []


# Expired entries


def test_an_expired_entry_fails():
    problems = check(one_exception(expired_at="2026-10-07"), TODAY)

    assert problems == [
        f"{ENTRY}: expired on 2026-10-07: remove it, or review it and set a new date"
    ]


def test_an_entry_is_already_expired_on_its_expiry_date():
    # Trivy stops honouring an entry at 00:00 UTC on that date.
    problems = check(one_exception(expired_at=TODAY), TODAY)

    assert problems == [
        f"{ENTRY}: expired on 2026-10-08: remove it, or review it and set a new date"
    ]


# Entries that expire too far out


def test_an_entry_expiring_one_day_past_the_limit_fails():
    problems = check(one_exception(expired_at=in_days(MAX_DAYS + 1)), TODAY)

    assert problems == [
        f"{ENTRY}: expires on 2027-01-07, more than 90 days away: "
        "the latest date allowed today is 2027-01-06"
    ]


def test_an_entry_cannot_be_made_permanent_with_a_far_future_date():
    assert len(check(one_exception(expired_at="2099-01-01"), TODAY)) == 1


# Entries without a reason


@pytest.mark.parametrize(
    "statement",
    [
        None,  # left out
        "",  # a key with no value
        '""',
        '"   "',
        "42",  # a number is not a written reason
    ],
)
def test_an_entry_without_a_written_reason_fails(statement):
    problems = check(one_exception(statement=statement), TODAY)

    assert problems == [f"{ENTRY}: has no reason: write one in 'statement'"]


# Entries without a usable expiry date


@pytest.mark.parametrize(
    "expired_at",
    [
        None,  # left out: to Trivy the entry would never expire
        "",  # a key with no value
        '"2026-11-07"',  # quoted, so a string
        "2026-11-07T12:00:00Z",  # a time of day
        "2026-11-7",  # not YYYY-MM-DD
        "next month",
    ],
)
def test_an_entry_without_a_plain_expiry_date_fails(expired_at):
    problems = check(one_exception(expired_at=expired_at), TODAY)

    assert problems == [
        f"{ENTRY}: has no usable expiry date: write 'expired_at' as a plain date, YYYY-MM-DD"
    ]


def test_a_misspelt_expiry_key_does_not_count_as_an_expiry():
    text = one_exception(expired_at=None) + "    expires_at: 2026-11-07\n"

    assert check(text, TODAY) == [
        f"{ENTRY}: unknown key 'expires_at': Trivy would skip it",
        f"{ENTRY}: has no usable expiry date: write 'expired_at' as a plain date, YYYY-MM-DD",
    ]


def test_a_date_that_does_not_exist_is_reported_not_raised():
    problems = check(one_exception(expired_at="2026-02-30"), TODAY)

    assert len(problems) == 1
    assert problems[0].startswith("cannot be read: ")


# Anything Trivy would skip or misread


def test_a_misspelt_narrowing_key_fails_because_trivy_would_widen_the_exception():
    text = one_exception() + "    purl: [pkg:pypi/example@1.0]\n"

    assert check(text, TODAY) == [f"{ENTRY}: unknown key 'purl': Trivy would skip it"]


def test_a_misspelt_section_fails():
    text = one_exception().replace("vulnerabilities:", "vulnerabilites:")

    assert check(text, TODAY) == ["unknown section 'vulnerabilites': Trivy would skip it"]


def test_an_entry_without_an_id_fails():
    text = f"vulnerabilities:\n  - statement: {REASON}\n    expired_at: 2026-11-07\n"

    assert check(text, TODAY) == ["vulnerabilities entry 1: has no id"]


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("- id: CVE-2099-0001\n", "must be a mapping of sections, such as 'vulnerabilities:'"),
        (
            "vulnerabilities: CVE-2099-0001\n",
            "section 'vulnerabilities' must be a list of exceptions",
        ),
        (
            "vulnerabilities:\n  - CVE-2099-0001\n",
            "vulnerabilities entry 1: must be a mapping with id, statement and expired_at",
        ),
    ],
)
def test_a_file_of_the_wrong_shape_fails(text, problem):
    assert check(text, TODAY) == [problem]


def test_text_that_is_not_yaml_is_reported_not_raised():
    problems = check("vulnerabilities: [unclosed\n", TODAY)

    assert len(problems) == 1
    assert problems[0].startswith("cannot be read: ")


def test_a_second_yaml_document_fails_because_trivy_reads_only_the_first():
    problems = check(one_exception() + "---\n" + one_exception(), TODAY)

    assert len(problems) == 1
    assert problems[0].startswith("cannot be read: ")


# Reporting


def test_every_problem_in_the_file_is_reported():
    text = """\
vulnerabilities:
  - id: CVE-2099-0001
    statement: The service never calls the affected function.
    expired_at: 2026-11-07
  - id: CVE-2099-0002
    expired_at: 2026-10-01
secrets:
  - id: example-rule
    statement: A placeholder in a fixture, not a credential.
    expired_at: 2027-10-08
"""

    assert check(text, TODAY) == [
        "vulnerabilities entry 2 (CVE-2099-0002): has no reason: write one in 'statement'",
        "vulnerabilities entry 2 (CVE-2099-0002): expired on 2026-10-01: "
        "remove it, or review it and set a new date",
        "secrets entry 1 (example-rule): expires on 2027-10-08, more than 90 days away: "
        "the latest date allowed today is 2027-01-06",
    ]


# The command line, which takes today's date from the clock


def test_the_command_exits_0_and_says_so_when_the_file_is_acceptable(tmp_path, capsys):
    next_month = datetime.datetime.now(datetime.UTC).date() + datetime.timedelta(days=30)
    path = tmp_path / ".trivyignore.yaml"
    path.write_text(one_exception(expired_at=next_month), encoding="utf-8")

    assert main([str(path)]) == 0
    assert capsys.readouterr().out.startswith(f"{path}: no exception is ")


def test_the_command_exits_1_and_names_the_file_and_the_problem(tmp_path, capsys):
    path = tmp_path / ".trivyignore.yaml"
    path.write_text(one_exception(expired_at="2026-01-01"), encoding="utf-8")

    assert main([str(path)]) == 1
    assert capsys.readouterr().err.startswith(f"{path}: {ENTRY}: expired on 2026-01-01")
