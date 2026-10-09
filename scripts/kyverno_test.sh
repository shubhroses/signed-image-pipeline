#!/usr/bin/env bash
# Run "kyverno test" on policy/ with the CLI pinned in versions.env.
#
# The container gets policy/ and deploy/ read-only and nothing else. It needs
# the network, because the test of the image policy asks about real images.
#
# "kyverno test" alone is not enough. When a policy does not match a fixture
# at all, the CLI reports the fixture as passed, with the reason "Excluded",
# whatever result the test expected. A policy that matched nothing would pass
# every one of its "fail" fixtures that way. So this script reads the table
# the CLI prints, and fails unless every fixture got a verdict from its policy.
# The one exception is the fixture that is there to show where a policy stops,
# and it must be reported as excluded: that also shows this check still
# understands the table.
#
# Usage, from the root of the repository:
#   KYVERNO_CLI_IMAGE=... scripts/kyverno_test.sh
set -euo pipefail

: "${KYVERNO_CLI_IMAGE:?is the pinned image in versions.env}"

OUTSIDE="require-requests-and-limits v1/Pod/elsewhere/outside-the-namespace"

results="$(mktemp)"
trap 'rm -f "$results"' EXIT

docker run --rm \
  --volume "$PWD/policy:/repo/policy:ro" \
  --volume "$PWD/deploy:/repo/deploy:ro" \
  --workdir /repo \
  "$KYVERNO_CLI_IMAGE" test policy/ --remove-color --detailed-results \
  | tee "$results"

# Columns 3, 5 and 7 of a row are the policy, the fixture and the reason. A
# Deployment has two rows under a policy written for Pods: excluded by the
# policy as written, judged by the check Kyverno derives from it.
without_verdict="$(awk -F ' *│ *' '
  $7 == "Ok" { judged[$3 " " $5] }
  $7 == "Excluded" { excluded[$3 " " $5] }
  END { for (fixture in excluded) if (!(fixture in judged)) print fixture }
' "$results")"

if [ "$without_verdict" != "$OUTSIDE" ]; then
  {
    echo "kyverno_test: only '$OUTSIDE' may go without a verdict, but these did:"
    echo "${without_verdict:-(none, not even that one)}"
  } >&2
  exit 1
fi
