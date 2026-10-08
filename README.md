# signed-image-pipeline

This will be a delivery pipeline in which a cluster runs only the images the pipeline vouches for: GitHub Actions scans a container image, records its SBOM, and signs and attests it with cosign, and a Kyverno admission policy admits nothing else.

It is under construction and is being built in order: a deliberately tiny app with its container and CI first, then the scan gate, the signed release, and the admission tests.

Until the full README replaces this note, nothing here is finished and nothing should be relied on.
