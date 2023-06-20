package main

import (
	"testing"
)

var (
	image = "localhost:5001/demo-refer:app3"
)

func Test_Cosign2(t *testing.T) {
	main()
}

func test_keyless(t *testing.T) {
	keyless_sigantureVerification(t, ctx)
}
