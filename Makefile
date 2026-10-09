# Local entry points.
#
#   make build    build the image as signed-image-pipeline:local
#   make test     unit tests, the scan exceptions and the policy fixtures
#   make scan     build the image and run the scan gate on it
#   make verify   check who signed a published image and attested its SBOM
#
# build, scan and verify need docker and nothing else. test also needs the
# Python packages of app/requirements-dev.txt.

# The pinned tool images: the file the workflows load.
include versions.env

IMAGE := signed-image-pipeline:local
REVISION := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

# What make verify checks: the image the release workflow built from the
# commit that is checked out. To check another one, pass its reference:
#   make verify RELEASE=ghcr.io/shubhroses/signed-image-pipeline@sha256:...
RELEASE := ghcr.io/shubhroses/signed-image-pipeline:$(REVISION)

# Who must have signed it: the release workflow of this repository, run on
# main. Sigstore writes the workflow and the ref of the run that asked into
# the signing certificate, on the word of the issuer, GitHub's token service.
IDENTITY := https://github.com/shubhroses/signed-image-pipeline/.github/workflows/release.yml@refs/heads/main
ISSUER := https://token.actions.githubusercontent.com

# scripts/cosign.sh runs the pinned cosign, with this directory as its home.
export COSIGN_IMAGE
export COSIGN_HOME ?= $(CURDIR)/.cache/cosign

# scripts/kyverno_test.sh runs the pinned Kyverno CLI.
export KYVERNO_CLI_IMAGE

.PHONY: build test scan verify

build:
	docker build --build-arg "REVISION=$(REVISION)" --tag "$(IMAGE)" .

# What ci.yml checks without building an image, less the linters.
test:
	python3 -m pytest
	python3 scripts/check_scan_exceptions.py .trivyignore.yaml
	scripts/kyverno_test.sh

# The gate of ci.yml, with the same flags: Trivy reads the image from a
# read-only tarball and fails on a fixable High or Critical finding that
# .trivyignore.yaml does not accept.
scan: build
	mkdir -p .cache
	docker save --output .cache/image.tar "$(IMAGE)"
	docker run --rm \
		--volume "$(CURDIR)/.cache/image.tar:/image.tar:ro" \
		--volume "$(CURDIR)/.trivyignore.yaml:/.trivyignore.yaml:ro" \
		"$(TRIVY_IMAGE)" image --input /image.tar --no-progress \
		--exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed \
		--ignorefile /.trivyignore.yaml --show-suppressed

# The two questions the verify job of release.yml asks, which runs this target
# too. They need no login and no key: the image and what is attached to it are
# public, and the identity above is all there is to trust. The first asks for
# a statement about the image signed by that identity, and the second for an
# SBOM attested by it. cosign would print that SBOM as one long encoded line,
# so the output of the second is dropped; what it checked is still printed.
verify:
	scripts/cosign.sh verify \
		--certificate-identity "$(IDENTITY)" \
		--certificate-oidc-issuer "$(ISSUER)" "$(RELEASE)"
	scripts/cosign.sh verify-attestation --type spdxjson \
		--certificate-identity "$(IDENTITY)" \
		--certificate-oidc-issuer "$(ISSUER)" "$(RELEASE)" > /dev/null
