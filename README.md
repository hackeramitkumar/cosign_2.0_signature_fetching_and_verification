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