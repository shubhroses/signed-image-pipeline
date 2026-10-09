#!/usr/bin/env bash
# Run cosign from the image pinned in versions.env.
#
# The container gets one directory of the caller's and nothing else. It is
# cosign's home and its working directory: cosign keeps a registry login and
# its copy of Sigstore's trust root there, and a file named without a path on
# the command line is read from it or written to it. The container runs as
# the caller, so each side can read what the other wrote.
#
# Three variables are passed on, each only when it is set:
#   ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN
#     How a GitHub Actions job with "id-token: write" asks for a token that
#     says which workflow is running. cosign needs them to sign without a key.
#   COSIGN_PASSWORD
#     The password of a private key, when cosign is given one.
#
# Usage: COSIGN_IMAGE=... COSIGN_HOME=... scripts/cosign.sh ARGUMENT ...
set -euo pipefail

: "${COSIGN_IMAGE:?is the pinned image in versions.env}"
: "${COSIGN_HOME:?is the directory cosign may read and write}"
mkdir -p "$COSIGN_HOME"

# --interactive passes standard input on, which "cosign login" reads.
exec docker run --rm --interactive \
  --user "$(id -u):$(id -g)" \
  --volume "$COSIGN_HOME:/home/cosign" \
  --workdir /home/cosign \
  --env HOME=/home/cosign \
  --env ACTIONS_ID_TOKEN_REQUEST_URL \
  --env ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  --env COSIGN_PASSWORD \
  "$COSIGN_IMAGE" "$@"
