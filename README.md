## Requirements

- Docker
- Rekor CLI
- Go 1.20+

Note - This demonstration is about fetching and verification of signatures and signed artifacts. So I have a already signed image.

## Setup
1. Setup Environment variables
   ```
   export IMAGE_URI=<.............>
   export SIGSTORE_REKOR_PUBLIC_KEY=<path to rekor.pub key>
   ```
2. Replace the cosign.pub by your own key.


repo1="localhost:5001/demo-reffer"
repourl1="http://localhost:5001/v2/demo-reffer"
docker run -d --rm --label demo=referrers -e "REGISTRY_STORAGE_DELETE_ENABLED=true" -e "REGISTRY_VALIDATION_DISABLED=true" -p "127.0.0.1:5001:5000" registry:2
regctl registry set --tls=disabled localhost:5001
digest=$(regctl image digest --platform linux/amd64 regclient/regctl:edge)
regctl image copy regclient/regctl@${digest} ${repo1}:app

 syft packages -q "${repo1}:app" -o cyclonedx-json | regctl artifact put --subject "${repo1}:app" --artifact-type application/vnd.cyclonedx+json -m application/vnd.cyclonedx+json --annotation "org.opencontainers.artifact.description=CycloneDX JSON SBOM"

 syft packages -q "${repo1}:app" -o spdx-json | regctl artifact put --subject "${repo1}:app" --artifact-type application/spdx+json -m application/spdx+json --annotation "org.opencontainers.artifact.description=SPDX JSON SBOM"


repo2="localhost:5002/demo-reffer"
repourl2="http://localhost:5002/v2/demo-reffer"
mtIndex="application/vnd.oci.image.index.v1+json"
mtImage="application/vnd.oci.image.manifest.v1+json"
docker run -d --rm --label demo=referrers -p "127.0.0.1:5002:5000" ghcr.io/project-zot/zot-linux-amd64:latest
regctl registry set --tls=disabled localhost:5001
