# Build stage: the official Python image, used only to install the locked
# dependencies. The distroless project names this image as the build stage to
# pair with python3-debian13, because both are Python 3.13 on Debian 13.
FROM python:3.13-slim-trixie@sha256:bf44cdfcb76cd3b41e879bc058fc37ec5872002ccfde7fcb765e218cde0cd79c AS build

COPY app/requirements.txt /tmp/requirements.txt

# --require-hashes refuses any file whose hash is not in the lock.
# --only-binary unpacks wheels only, so no package's build script runs here.
# --root-user-action silences pip's warning about running as root, which is
# what a throwaway build stage is for.
RUN pip install \
        --no-cache-dir \
        --only-binary :all: \
        --require-hashes \
        --requirement /tmp/requirements.txt \
        --root-user-action ignore \
        --target /deps


# Final stage: distroless holds the Python runtime and what it needs to run.
# It has no shell, no package manager and no pip, so no build tools ship.
FROM gcr.io/distroless/python3-debian13:nonroot@sha256:83aa8d4f74a4d7f7cf2d472054139bef71a927b76c680c0f2e1021d6b1d6d732

COPY --from=build /deps /deps
COPY app/__init__.py app/main.py /srv/app/

# PYTHONPATH is how the interpreter finds the packages copied into /deps.
# The image is meant to run with a read-only root filesystem, so Python is told
# not to write .pyc files. Unbuffered output reaches the container log at once.
ENV PYTHONPATH=/deps \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

# The base image already runs as this user. It is repeated here by number so
# that Kubernetes can check runAsNonRoot against the image alone.
USER 65532:65532

EXPOSE 8080

# The commit the image was built from: GET /version reports it and the label
# records it.
ARG REVISION=unknown
ENV APP_REVISION=${REVISION}
LABEL org.opencontainers.image.source="https://github.com/shubhroses/signed-image-pipeline" \
      org.opencontainers.image.revision="${REVISION}"

ENTRYPOINT ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
