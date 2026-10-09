import sys

import pytest

from scripts.expect_failure import judge, main

WORDS = "no signatures found"
OUTPUT = "WARNING: something else first\nError: no signatures found\n"


# The verdict on a command that has already run


def test_a_failure_that_says_the_expected_words_is_a_refusal():
    assert judge(WORDS, 1, OUTPUT) == (True, "Error: no signatures found")


def test_any_failure_status_counts():
    refused, _ = judge(WORDS, 10, OUTPUT)

    assert refused


def test_a_command_that_succeeds_is_not_a_refusal():
    refused, line = judge(WORDS, 0, "verified\n")

    assert not refused
    assert "succeeded" in line


def test_a_command_that_succeeds_while_saying_the_words_is_not_a_refusal():
    refused, _ = judge(WORDS, 0, OUTPUT)

    assert not refused


def test_a_failure_that_says_something_else_is_not_a_refusal():
    refused, line = judge(WORDS, 1, "Error: connection refused\n")

    assert not refused
    assert "exit status 1" in line
    assert WORDS in line


def test_a_failure_that_says_nothing_is_not_a_refusal():
    refused, _ = judge(WORDS, 1, "")

    assert not refused


def test_the_words_must_be_on_one_line():
    refused, _ = judge(WORDS, 1, "Error: no signatures\nfound\n")

    assert not refused


def test_the_words_are_matched_exactly_as_written():
    refused, _ = judge(WORDS, 1, "Error: No Signatures Found\n")

    assert not refused


def test_the_first_line_that_holds_the_words_is_reported():
    output = f"Error: {WORDS}\nerror during command execution: {WORDS}\n"

    assert judge(WORDS, 1, output) == (True, f"Error: {WORDS}")


# The command line, running a real command


def python(code: str) -> list[str]:
    return [sys.executable, "-c", code]


FAILS_AS_EXPECTED = python(f"import sys; print('Error: {WORDS}', file=sys.stderr); sys.exit(10)")


def test_the_command_line_passes_and_prints_the_line_that_was_said(capsys):
    assert main([WORDS, *FAILS_AS_EXPECTED]) == 0

    captured = capsys.readouterr()
    assert captured.out == f"Error: {WORDS}\n"
    assert f"Error: {WORDS}" in captured.err  # the command's own output is passed on


def test_the_command_line_reads_standard_output_as_well_as_standard_error():
    command = python(f"import sys; print('Error: {WORDS}'); sys.exit(1)")

    assert main([WORDS, *command]) == 0


def test_the_command_line_fails_when_the_command_succeeds(capsys):
    assert main([WORDS, *python(f"print('{WORDS}')")]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "succeeded" in captured.err


def test_the_command_line_fails_when_the_command_fails_for_another_reason(capsys):
    command = python("import sys; print('Error: timeout', file=sys.stderr); sys.exit(1)")

    assert main([WORDS, *command]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Error: timeout" in captured.err
    assert "did not say" in captured.err


def test_the_command_line_fails_when_the_command_cannot_be_started(capsys):
    assert main([WORDS, "/nonexistent/command"]) == 1
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("arguments", [[], [WORDS], ["", "true"], ["  ", "true"]])
def test_the_command_line_needs_words_and_a_command(arguments, capsys):
    assert main(arguments) == 2
    assert "usage" in capsys.readouterr().err
