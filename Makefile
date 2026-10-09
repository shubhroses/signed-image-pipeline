# Local entry points.
#
#   make build       build the image as signed-image-pipeline:local
#   make test        unit tests, the scan exceptions and the policy fixtures
#   make scan        build the image and run the scan gate on it
#   make verify      check who signed a published image and attested its SBOM
#   make admission   try the accept and reject cases on a kind cluster
#
# build, scan and verify need docker and nothing else. test also needs the
# Python packages of app/requirements-dev.txt. admission also needs kind,
# kubectl, helm and jq, and makes a cluster of its own to run in.

# The pinned tool images: the file the workflows load.
include versions.env

IMAGE := signed-image-pipeline:local
REVISION := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

# What make verify and make admission check: the image the release workflow
# built from the commit that is checked out. To check another one, pass its
# reference:
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

# What else make admission takes from that run of the release workflow: the
# tag of the release, and the three images built to be refused.
RELEASE_TAG := ghcr.io/shubhroses/signed-image-pipeline:$(REVISION)
FIXTURES := ghcr.io/shubhroses/signed-image-pipeline-fixtures
UNSIGNED := $(FIXTURES):unsigned-$(REVISION)
WRONG_SIGNER := $(FIXTURES):wrong-signer-$(REVISION)
NO_SBOM := $(FIXTURES):no-sbom-$(REVISION)

# make admission runs in a cluster of its own. kind makes it under this name
# and writes the credentials for it to this file, inside the repository, and
# to no other. Each kind, kubectl and helm command below names the cluster or
# its context, so none of them can act on a cluster that was there before.
# "override" keeps the file the same whatever KUBECONFIG is in the
# environment or on the command line.
CLUSTER := signed-image-pipeline
override KUBECONFIG := $(CURDIR)/.cache/kubeconfig
export KUBECONFIG
KUBECTL := kubectl --context "kind-$(CLUSTER)"

# The namespace and the policies to apply, and where the cases write the table
# of what the cluster did. scripts/admission_cases.sh reads the exported ones.
POLICY := policy
RESULTS := .cache/admission.md
export CLUSTER RELEASE RELEASE_TAG UNSIGNED WRONG_SIGNER NO_SBOM OUTSIDE_IMAGE RESULTS

.PHONY: build test scan verify
.PHONY: admission admission-cluster admission-policy admission-cases

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

# The admission job of release.yml, which runs the three targets below one by
# one. With no arguments it tests what that workflow published for the commit
# that is checked out, and deletes the cluster when every case went as
# expected. After a failure the cluster stays, to be looked at; the next run
# replaces it.
admission:
	$(MAKE) admission-cluster
	$(MAKE) admission-policy
	$(MAKE) admission-cases
	kind delete cluster --name "$(CLUSTER)" --kubeconfig "$(KUBECONFIG)"

# A new cluster, running the pinned Kubernetes, with the pinned Kyverno in it.
# The node image and the chart are fetched before they are used: a download
# can be tried again, and the commands that use them are not written to be.
admission-cluster:
	mkdir -p .cache
	kind delete cluster --name "$(CLUSTER)" --kubeconfig "$(KUBECONFIG)"
	python3 scripts/retry.py docker pull --quiet "$(KIND_NODE_IMAGE)"
	kind create cluster --name "$(CLUSTER)" --kubeconfig "$(KUBECONFIG)" \
		--image "$(KIND_NODE_IMAGE)" --wait 120s
	python3 scripts/retry.py helm pull kyverno \
		--repo https://kyverno.github.io/kyverno \
		--version "$(KYVERNO_CHART_VERSION)" --destination .cache
	helm install kyverno ".cache/kyverno-$(KYVERNO_CHART_VERSION).tgz" \
		--kube-context "kind-$(CLUSTER)" --namespace kyverno --create-namespace \
		--wait --timeout 5m

# The namespace and the two policies, exactly as the files in policy/ have
# them, and then a wait until Kyverno reports that it enforces both. Only a
# rehearsal of the release workflow on another ref passes another POLICY.
admission-policy:
	python3 scripts/retry.py $(KUBECTL) apply --filename "$(POLICY)/"
	python3 scripts/retry.py $(KUBECTL) wait --timeout=120s \
		--for=jsonpath='{.status.conditionStatus.ready}'=true \
		imagevalidatingpolicy/verify-release-image \
		validatingpolicy/require-requests-and-limits

admission-cases:
	scripts/admission_cases.sh
