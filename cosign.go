package main

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

var (
	pub_key = `-----BEGIN PUBLIC KEY-----
	MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjUlDDji3rnrJpceDaw/fRo5ZGhbJ
	ehPAoLSiNJSNRU7AZV+srW6k+1ITu0NVMmwUqL/83Ug0etoSaCiW71b9Hg==
	-----END PUBLIC KEY-----`
)

type sig struct {
	oci.Signature
	cosignPayload cosign.SignedPayload
}

func extractPayload(verified []oci.Signature) ([]payload.SimpleContainerImage, error) {
	var sigPayloads []payload.SimpleContainerImage
	fmt.Println("1")
	for _, b := range verified {
		fmt.Println(b)
	}
	for _, sig := range verified {
		fmt.Println("2")
		if sig != nil {
			fmt.Println(sig)
			// pld, err := sig.Payload()
			fmt.Println("3")

			// if err != nil {
			// 	return nil, fmt.Errorf("failed to get payload: %w", err)
			// }

			sci := payload.SimpleContainerImage{}
			// if err := json.Unmarshal(pld, &sci); err != nil {
			// 	return nil, fmt.Errorf("error decoding the payload: %w", err)
			// }
			fmt.Println("4")

			sigPayloads = append(sigPayloads, sci)
		}
	}
	return sigPayloads, nil
}

func decodePEM(raw []byte, signatureAlgorithm crypto.Hash) (signature.Verifier, error) {
	// PEM encoded file.
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("pem to public key: %w", err)
	}
	return signature.LoadVerifier(pubKey, signatureAlgorithm)
}

func verifyImageSignatures_util(ctx context.Context, ref name.Reference) ([]oci.Signature, error) {

	verifier, err := decodePEM([]byte(pub_key), crypto.SHA256)
	if err != nil {
		fmt.Println("Error occured during the fetching of verifier;")
		panic(err)
	}

	cosignVeriOptions := cosign.CheckOpts{
		SigVerifier: verifier,
	}

	fmt.Println("Public Key", verifier.PublicKey)
	fmt.Println("Verify signature : ", verifier.VerifySignature)
	fmt.Println("Sig.Verifier", verifier)

	verified_signatures, isVerified, err := cosign.VerifyImageSignatures(ctx, ref, &cosignVeriOptions)
	fmt.Println("-------------------------Signature verification in Progress ---------------------------")
	if err != nil {
		fmt.Println("No signature matched : ")
		panic(err)
	}

	if !isVerified {
		panic("-------------Verification failed --------------------")
	}

	fmt.Println("------------------------- Signature verification completed  ---------------------------")
	return verified_signatures, err

}

func fetchArtifacts(ref name.Reference) error {
	desc, err := remote.Get(ref)
	if err != nil {
		fmt.Errorf("Got some error", err)
		return err
	}

	byteStream, err := json.Marshal(desc.Descriptor)
	jsonString := string(byteStream)
	fmt.Println(jsonString)
	return nil
}

func main() {
	image := "ghcr.io/hackeramitkumar/kubeji2:latest"
	ref, err := name.ParseReference(image)
	if err != nil {
		panic(err)
	}
	fmt.Println("--------------------------------Image refrence information : ----------------------------------")
	fmt.Println("Registry : ", ref.Context().RegistryStr())
	fmt.Println("Repository : ", ref.Context().RepositoryStr())
	fmt.Println("Identifier : ", ref.Identifier())

	fmt.Printf("------------------------Fetching the signedPayload for : ", image)
	fmt.Println("---------------------------------------------")

	ctx := context.Background()
	signedPayloads, err := cosign.FetchSignaturesForReference(ctx, ref)
	if err != nil {
		fmt.Println("Error During signedPayloads Fetcheing ")
		panic(err)
	}

	fmt.Println("------------------------------------- Fetched all the signedPayloads ------------------------------------------------------")
	fmt.Println()

	for _, Payload := range signedPayloads {
		fmt.Println("------------------------------------- Signed Payload  -------------------------------------------------------")
		fmt.Println("\n \n------------------------------------- Signed Payload Bundle  -------------------------------------------------------")

		byteStream, err := json.Marshal(Payload.Bundle)
		if err != nil {
			fmt.Println("Error marshaling JSON:", err)
			return
		}
		jsonString := string(byteStream)
		fmt.Println(jsonString)
		fmt.Printf("-----------------------------------  Signature for Payload :  --------------------------------------:\n ")
		fmt.Println(Payload.Base64Signature)
		fmt.Printf("------------------------------------ Certificate for the Payload : ---------------------------------------------: \n")
		byteStream2, err := json.Marshal(Payload.Cert)
		// sigVer, err := cosign.ValidateAndUnpackCert(Payload.Cert)

		if err != nil {
			fmt.Println("Error marshaling JSON:", err)
			return
		}
		jsonString2 := string(byteStream2)
		fmt.Println(jsonString2)

		// verification by using the certificate

	}

	fmt.Println("----------------------Artifacts----------------------------------")
	fetchArtifacts(ref)

	img, err := remote.Image(ref)
	manifest, err := img.Manifest()
	byteStream3, err := json.Marshal(manifest)
	jsonString3 := string(byteStream3)
	fmt.Println("manifest :", jsonString3)

	fmt.Println("------------------------------------Signature verification --------------------------------------------")

	buffer_key := []byte(pub_key)
	fmt.Println()

	stringstr4 := string(buffer_key)
	fmt.Println("The public key is : ", stringstr4)

	verified_signatures, err := verifyImageSignatures_util(ctx, ref)
	fmt.Println("List of the verified signatures ----------------::::::")
	for _, sig := range verified_signatures {
		fmt.Println(sig.Base64Signature)
	}

}
