#!/usr/bin/env bash
# The eight cases of the admission test: two workloads the cluster has to
# accept and six it has to refuse.
#
# The cluster must already have Kyverno, the namespace and the policies; the
# Makefile's admission targets see to that and call this. Every kubectl call
# names the context that kind made for the test cluster, so that a kubeconfig
# without it stops the script and no other cluster is ever asked.
#
# The first case rolls out deploy/ with the released image. Each of the others
# is a Pod made from the Pod template of that Deployment with one thing
# changed. The template has just been admitted and has become Ready, so a Pod
# that is refused is refused for the one change. A refusal counts only when
# the API server names the policy expected to refuse (scripts/expect_failure.py).
#
# All eight cases are tried even when one goes wrong. The table of what the
# cluster did is written to $RESULTS, and the script fails if any case did not
# go as expected.
#
# Usage: make admission-cases, or with all of the variables below set.
set -euo pipefail

: "${CLUSTER:?is the name of the kind cluster of the test}"
: "${RELEASE:?is the released image, by digest or by tag}"
: "${RELEASE_TAG:?is a tag of the released image}"
: "${UNSIGNED:?is the fixture nobody signed}"
: "${WRONG_SIGNER:?is the fixture signed with a throwaway key}"
: "${NO_SBOM:?is the fixture signed by the workflow, with no SBOM attested}"
: "${OUTSIDE_IMAGE:?is the image from another registry in versions.env}"
: "${RESULTS:?is the file to write the table of results to}"

kubectl=(kubectl --context "kind-$CLUSTER" --namespace apps)

# What a refusal has to say. The first three are a policy's name and one of
# its messages, as Kyverno reports them; the last is how Pod Security
# Admission names the standard a Pod breaks.
NOT_SIGNED="Policy verify-release-image failed: no signature by the release workflow on main"
NO_SBOM_ATTESTED="Policy verify-release-image failed: no SBOM attested by the release workflow on main"
NO_LIMITS="Policy require-requests-and-limits failed: every container must set CPU and memory requests and limits"
POD_SECURITY='violates PodSecurity "restricted:'

# The cases need the release by digest. Given by tag, it is looked up in the
# registry once, here.
case "$RELEASE" in
  *@sha256:*) ;;
  *)
    digest="$(docker buildx imagetools inspect --format '{{json .Manifest}}' "$RELEASE" \
      | jq --raw-output --exit-status .digest)"
    RELEASE="${RELEASE%:*}@$digest"
    ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# deploy/ as committed, except that its image is the release under test.
cp -R deploy "$work/deploy"
sed "s|^\( *image: \).*|\1$RELEASE|" deploy/deployment.yaml > "$work/deploy/deployment.yaml"
grep --quiet --fixed-strings "image: $RELEASE" "$work/deploy/deployment.yaml"

mkdir -p "$(dirname "$RESULTS")"
{
  echo "| Case | Workload | Expected | What the cluster did |"
  echo "|---|---|---|---|"
} > "$RESULTS"

failures=0

# Try one case and add its row to the table. After the letter of the case,
# the workload and what is expected comes a command that prints what the
# cluster did and fails unless that is what the case expects.
#
# The command runs in a subshell with "set -e" of its own. Called from an
# "if", bash would carry on past a failing line inside it.
try() {
  local letter="$1" workload="$2" expected="$3" started="$SECONDS" seen status
  shift 3
  printf '\n=== Case %s: %s\n' "$letter" "$workload" >&2
  set +e
  seen="$(set -e; "$@")"
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    seen="**Not as expected.** ${seen:-See the log of this step.}"
    failures=$((failures + 1))
  fi
  echo "    after $((SECONDS - started)) s: $seen" >&2
  # A "|" in an answer would otherwise end the cell of the table.
  printf '| %s | %s | %s | %s |\n' "$letter" "$workload" "$expected" "${seen//|/\\|}" >> "$RESULTS"
}

# Case a. The Deployment has to be admitted, its Pods have to be admitted and
# become Ready, and the image the node reports for them has to be the digest
# that was released.
rolls_out() {
  python3 scripts/retry.py "${kubectl[@]}" apply --filename "$work/deploy/" >&2
  "${kubectl[@]}" rollout status deployment/signed-image-pipeline --timeout=180s >&2
  running="$("${kubectl[@]}" get pods --selector app.kubernetes.io/name=signed-image-pipeline \
    --output jsonpath='{range .items[*]}{.status.containerStatuses[0].imageID}{"\n"}{end}' \
    | sort --unique)"
  ready="$("${kubectl[@]}" get deployment signed-image-pipeline \
    --output jsonpath='{.status.readyReplicas} of {.spec.replicas}')"
  if [ "$running" != "$RELEASE" ]; then
    echo "Rolled out, but running \`$running\`"
    return 1
  fi
  echo "Rolled out: $ready replicas Ready, running \`$running\`"
}

# Write $work/NAME.json: a Pod with the spec of the Deployment's Pod template
# and the image IMAGE, and with whatever else the jq expression EDIT changes.
# The Pod has none of the template's labels, so the Service does not take it
# for one of the replicas.
#
# Usage: pod NAME IMAGE [EDIT]
pod() {
  # $name and $image are jq's variables, set by --arg, and not the shell's.
  "${kubectl[@]}" get deployment signed-image-pipeline --output json \
    | jq --arg name "$1" --arg image "$2" '
        {apiVersion: "v1", kind: "Pod", metadata: {name: $name}, spec: .spec.template.spec}
        | .spec.containers[0].image = $image
        | '"${3:-.}" > "$work/$1.json"
}

# Case b. Kyverno has to replace the tag with the digest it points at before
# the Pod is stored, and that digest has to be the released one.
admitted_by_tag() {
  pod case-b "$RELEASE_TAG"
  python3 scripts/retry.py "${kubectl[@]}" create --filename "$work/case-b.json" >&2
  stored="$("${kubectl[@]}" get pod case-b --output jsonpath='{.spec.containers[0].image}')"
  case "$stored" in
    *"@${RELEASE##*@}")
      echo "Admitted, and stored as \`$stored\`"
      ;;
    *)
      echo "Admitted, but stored as \`$stored\`"
      return 1
      ;;
  esac
}

# Cases c to h. The Pod must be refused, and the refusal must contain WORDS.
# What is printed is the API server's answer, without the name of the file
# that kubectl puts in front of it.
#
# Usage: refused NAME WORDS IMAGE [EDIT]
refused() {
  pod "$1" "$3" "${4:-.}"
  if answer="$(python3 scripts/expect_failure.py "$2" \
    "${kubectl[@]}" create --filename "$work/$1.json")"; then
    echo "Refused: \`${answer#*\": }\`"
  else
    echo "Not refused with \`$2\`. See the log of this step."
    return 1
  fi
}

try a "\`deploy/\` at the released digest" \
  "Rolls out and becomes Ready" \
  rolls_out
try b "The same image referenced by tag" \
  "Admitted, and the stored Pod spec carries the digest" \
  admitted_by_tag
try c "Unsigned fixture" \
  "Rejected by the image policy" \
  refused case-c "$NOT_SIGNED" "$UNSIGNED"
try d "Wrong-signer fixture" \
  "Rejected by the image policy" \
  refused case-d "$NOT_SIGNED" "$WRONG_SIGNER"
try e "No-SBOM fixture" \
  "Rejected by the image policy" \
  refused case-e "$NO_SBOM_ATTESTED" "$NO_SBOM"
try f "A public image from another registry (\`${OUTSIDE_IMAGE%%[:@]*}\`)" \
  "Rejected by the image policy" \
  refused case-f "$NOT_SIGNED" "$OUTSIDE_IMAGE"
try g "The released image with \`runAsUser: 0\`" \
  "Rejected by Pod Security Admission" \
  refused case-g "$POD_SECURITY" "$RELEASE" '.spec.containers[0].securityContext.runAsUser = 0'
try h "The released image without resource limits" \
  "Rejected by the validate policy" \
  refused case-h "$NO_LIMITS" "$RELEASE" 'del(.spec.containers[0].resources.limits)'

echo >&2
cat "$RESULTS"
if [ "$failures" -ne 0 ]; then
  echo "admission_cases: $failures of the eight cases did not go as expected" >&2
  exit 1
fi
