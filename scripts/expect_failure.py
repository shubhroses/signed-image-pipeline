"""Run a command that has to fail, and check that it fails for the right reason.

A negative test passes when something is refused. A refusal alone proves
little: a misspelt image name is refused too, and so is everything while a
registry is down. So the command must end with a failure status and must say
why, in words the caller gives. A command that succeeds fails this check, and
so does one that fails while saying something else.

Everything the command prints goes to standard error, where a job log shows
it. The line that holds the expected words goes to standard output, so that
the caller can record what was said.

The command is run once. A refusal is an answer, and this check does not ask
again in the hope of a different one. Only the standard library is used, so
that a job can call this with the runner's own python3 and install nothing.

Usage: python3 scripts/expect_failure.py EXPECTED_WORDS COMMAND [ARGUMENT ...]
"""

import subprocess
import sys
from collections.abc import Sequence


def judge(expected: str, status: int, output: str) -> tuple[bool, str]:
    """Return whether the command was refused as expected, and one line to report.

    The line is the command's own, the one holding the expected words, when it
    was; otherwise it says what happened instead.
    """
    if status == 0:
        return False, "the command succeeded, and it had to fail"
    for line in output.splitlines():
        if expected in line:
            return True, line.strip()
    return False, f"the command failed with exit status {status}, but did not say '{expected}'"


def run(command: Sequence[str]) -> tuple[int, str]:
    """Run the command and return its exit status with all that it printed."""
    # The lint rule S603 asks whether a command built from input is safe to
    # run. Running the caller's command is the purpose here, and it is run
    # as given, without a shell to interpret it.
    finished = subprocess.run(  # noqa: S603
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        check=False,
    )
    return finished.returncode, finished.stdout


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    # Blank words are in every line, so they would accept any failure at all.
    if len(arguments) < 2 or not arguments[0].strip():
        print(
            "usage: python3 scripts/expect_failure.py EXPECTED_WORDS COMMAND [ARGUMENT ...]",
            file=sys.stderr,
        )
        return 2
    expected, command = arguments[0], arguments[1:]

    try:
        status, output = run(command)
    except OSError as error:  # the command could not be started at all
        print(f"expect_failure: {error}", file=sys.stderr)
        return 1
    sys.stderr.write(output)

    refused, line = judge(expected, status, output)
    if not refused:
        print(f"expect_failure: {line}", file=sys.stderr)
        return 1
    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
