package main

import (
	"testing"
)

var (
	image = "localhost:5001/demo-refer:app3"
)

func test_Cosign2(t *testing.T) {
	main()
}

func test_fetch_signatures_and_manifests(t *testing.T) {
	cosign2(image)
}

func test_keyed(t *testing.T) {
	keyed_signatureVerification(image)
}

func test_keyless(t *testing.T) {
	keyless_sigantureVerification(image)
}

func test_fetch_attached_artifacts_using_referrer_API(t *testing.T) {
	fetch_attestations(image)
}

func test_verify_attestation(t *testing.T) {
	verifyAttestaions(image)
}
