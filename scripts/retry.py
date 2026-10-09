"""Run a command, and run it again if it fails.

A release depends on services it does not control, and a registry that fails
once usually answers the second time. This is for a step that only fetches or
sends something, such as a push or a pull. It is not for a step that decides
something, such as the scan gate: when that fails the answer is "no", and
asking again does not make it "yes".

Each attempt starts the command afresh with the same arguments, so the command
must not read standard input. Only the standard library is used, so that a job
can call this with the runner's own python3 and install nothing.

Usage: python3 scripts/retry.py COMMAND [ARGUMENT ...]
"""

import subprocess
import sys
import time
from collections.abc import Callable, Sequence

ATTEMPTS = 3
PAUSE_SECONDS = 10  # after the first failure; twice as long after the second


def retry(
    command: Sequence[str],
    run: Callable[[Sequence[str]], int] = subprocess.call,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Return 0 as soon as an attempt succeeds, or else the last exit status."""
    for attempt in range(1, ATTEMPTS):
        status = run(command)
        if status == 0:
            return 0
        pause = PAUSE_SECONDS * attempt
        print(
            f"attempt {attempt} of {ATTEMPTS} failed with exit status {status}; "
            f"trying again in {pause} seconds",
            file=sys.stderr,
        )
        sleep(pause)
    return run(command)


def main(argv: list[str] | None = None) -> int:
    command = sys.argv[1:] if argv is None else argv
    if not command:
        print("usage: python3 scripts/retry.py COMMAND [ARGUMENT ...]", file=sys.stderr)
        return 2
    return retry(command)


if __name__ == "__main__":
    sys.exit(main())
