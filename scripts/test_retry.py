import sys

from scripts.retry import ATTEMPTS, PAUSE_SECONDS, main, retry

COMMAND = ["docker", "push", "example"]


class Command:
    """Stands in for running a command: each run ends with the next status given."""

    def __init__(self, *statuses: int):
        self.statuses = list(statuses)
        self.runs = []

    def __call__(self, command):
        self.runs.append(command)
        return self.statuses.pop(0)


class Clock:
    """Stands in for time.sleep and records how long each pause was."""

    def __init__(self):
        self.pauses = []

    def __call__(self, seconds):
        self.pauses.append(seconds)


def test_a_command_that_succeeds_runs_once():
    run, sleep = Command(0), Clock()

    assert retry(COMMAND, run, sleep) == 0
    assert run.runs == [COMMAND]
    assert sleep.pauses == []


def test_a_command_that_fails_is_run_again_with_the_same_arguments():
    run, sleep = Command(1, 0), Clock()

    assert retry(COMMAND, run, sleep) == 0
    assert run.runs == [COMMAND, COMMAND]


def test_a_command_may_succeed_on_the_last_attempt():
    run = Command(*[1] * (ATTEMPTS - 1), 0)

    assert retry(COMMAND, run, Clock()) == 0
    assert len(run.runs) == ATTEMPTS


def test_a_command_that_keeps_failing_fails_with_its_last_exit_status():
    run = Command(*[1] * (ATTEMPTS - 1), 7)

    assert retry(COMMAND, run, Clock()) == 7
    assert len(run.runs) == ATTEMPTS


def test_each_pause_is_longer_and_there_is_none_after_the_last_attempt():
    sleep = Clock()

    retry(COMMAND, Command(*[1] * ATTEMPTS), sleep)

    assert sleep.pauses == [PAUSE_SECONDS, 2 * PAUSE_SECONDS]


def test_a_failure_says_which_attempt_failed_and_how(capsys):
    retry(COMMAND, Command(5, 0), Clock())

    assert f"attempt 1 of {ATTEMPTS} failed with exit status 5" in capsys.readouterr().err


# The command line, running a real command


def python(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_the_command_line_runs_a_real_command():
    assert main(python("raise SystemExit(0)")) == 0


def test_the_command_line_passes_on_the_exit_status_of_a_real_failure(monkeypatch):
    monkeypatch.setattr("scripts.retry.PAUSE_SECONDS", 0)

    assert main(python("raise SystemExit(3)")) == 3


def test_the_command_line_needs_a_command(capsys):
    assert main([]) == 2
    assert "usage" in capsys.readouterr().err
