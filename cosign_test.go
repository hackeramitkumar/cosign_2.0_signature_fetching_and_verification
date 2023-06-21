package main

import "testing"

var (
	image        = "localhost:5001/demo-reffer:app3"
	artifactType = "application/spdx+json"
)

func Test_Cosign2(t *testing.T) {
	main()
}

func Test_fetch_signatures_and_manifests(t *testing.T) {
	images_manifest_and_signature_fetch(image)
}

func Test_keyed_signature_verification(t *testing.T) {
	keyed_signatureVerification(image)
}

func Test_keyless_signature_verification(t *testing.T) {
	keyless_sigantureVerification(image)
}

func Test_fetch_attached_artifacts_using_referrer_API(t *testing.T) {
	fetch_attestations(image, artifactType)
}

func Test_verify_attestation(t *testing.T) {
	verifyAttestaions(image)
}
