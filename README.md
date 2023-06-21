## Requirements

- Docker
- Cosign CLI
- Go 1.20+
- Regctl


Note - Paste your cosign public key in cosign.pub file.

## Setup for running the demo :


 ```
1. repo1="localhost:5001/demo-reffer"

 ```

We can use any registry which supports OCI 1.1 
 ```
 2. docker run -d --rm --label demo=referrers -e "REGISTRY_STORAGE_DELETE_ENABLED=true" -e "REGISTRY_VALIDATION_DISABLED=true" -p "127.0.0.1:5001:5000" registry:2
```

```
3. regctl registry set --tls=disabled localhost:5001
```

It will fetch the digest for linux/amd64 image from a multiplatform image
```
4. digest=$(regctl image digest --platform linux/amd64 regclient/regctl:edge)
```


```
5. regctl image copy regclient/regctl@${digest} ${repo1}:app
```


```
6. syft packages -q "${repo1}:app" -o cyclonedx-json | regctl artifact put --subject "${repo1}:app" --artifact-type application/vnd.cyclonedx+json -m application/vnd.cyclonedx+json --annotation "org.opencontainers.artifact.description=CycloneDX JSON SBOM"
```


```
7. syft packages -q "${repo1}:app" -o spdx-json | regctl artifact put --subject "${repo1}:app" --artifact-type application/spdx+json -m application/spdx+json --annotation "org.opencontainers.artifact.description=SPDX JSON SBOM"

```

Note -> Since cosign does not support these type of refferes so for performing artifact verification we have to add in toto attestation by using cosign CLI.

```
8. cosign attest --predicate <file> --key cosign.key <image>
```




<!-- 
1. repourl1="http://localhost:5001/v2/demo-reffer"

repo2="localhost:5002/demo-reffer"
repourl2="http://localhost:5002/v2/demo-reffer"
mtIndex="application/vnd.oci.image.index.v1+json"
mtImage="application/vnd.oci.image.manifest.v1+json"
docker run -d --rm --label demo=referrers -p "127.0.0.1:5002:5000" ghcr.io/project-zot/zot-linux-amd64:latest
regctl registry set --tls=disabled localhost:5001

 -->
