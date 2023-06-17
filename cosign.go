package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func decodePEM(raw []byte, signatureAlgorithm crypto.Hash) (signature.Verifier, error) {
	// PEM encoded file.
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("pem to public key: %w", err)
	}
	return signature.LoadVerifier(pubKey, signatureAlgorithm)
}

func fetchArtifacts(ref name.Reference) error {
	desc, err := remote.Get(ref)
	if err != nil {
		panic(err)
	}

	byteStream, err := json.Marshal(desc.Descriptor)
	if err != nil {
		fmt.Println("error during the marshaling of descriptor")
		panic(err)
	}
	jsonString := string(byteStream)
	fmt.Println(jsonString)

	img, err := remote.Image(ref)
	if err != nil {
		panic(err)
	}
	manifest, err := img.Manifest()
	if err != nil {
		panic(err)
	}
	byteStream3, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	jsonString3 := string(byteStream3)
	fmt.Println("manifest :", jsonString3)

	return nil
}

func loadCert(pem []byte) (*x509.Certificate, error) {
	var out []byte
	out, err := base64.StdEncoding.DecodeString(string(pem))
	if err != nil {
		// not a base64
		out = pem
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(out)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate from PEM format: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certs found in pem file")
	}
	return certs[0], nil
}

func keyed_signatureVerification(ctx context.Context, ref name.Reference) ([]oci.Signature, error) {
	filePath := "cosign.pub"
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		panic(err)
	}

	// Convert the data to a byte slice ([]byte)
	byteData := []byte(data)
	verifier, err := decodePEM(byteData, crypto.SHA256)
	if err != nil {
		fmt.Println("Error occured during the fetching of verifier;")
		panic(err)
	}

	trustedTransparencyLogPubKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		fmt.Println("Error occured during the getting rekor pubs keys...")
	}
	fmt.Println("Rekor keys are : ", trustedTransparencyLogPubKeys.Keys)
	// rekor_client := cosign.Get(ctx)
	cosignVeriOptions := cosign.CheckOpts{
		SigVerifier: verifier,
		// RekorClient: rekor_client,
		RekorPubKeys: trustedTransparencyLogPubKeys,
	}

	/*
		fmt.Println("Public Key", verifier.PublicKey)
		fmt.Println("Verify signature : ", verifier.VerifySignature)
		fmt.Println("Sig.Verifier", verifier)
	*/

	verified_signatures, isVerified, err := cosign.VerifyImageSignatures(ctx, ref, &cosignVeriOptions)
	fmt.Println("-----------------------------Signature verification in Progress -------------------------------")
	if err != nil {
		fmt.Println("No signature matched : ")
	}

	if !isVerified {
		fmt.Println("---------------------------------Verification failed ----------------------------------------")
	}
	fmt.Println("")

	fmt.Println("---------------------------- Signature verification completed  ----------------------------------")
	return verified_signatures, err

}

func keyless_sigantureVerification(ctx context.Context, ref name.Reference) ([]oci.Signature, error) {

	identities := []cosign.Identity{
		cosign.Identity{
			Issuer:  "https://accounts.google.com",
			Subject: "amit9116260192@gmail.com",
		},
	}

	trustedTransparencyLogPubKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		fmt.Println("Error occured during the getting rekor pubs keys...")
	}
	fmt.Println("Rekor keys are : ", trustedTransparencyLogPubKeys.Keys)

	filePath := "demo.txt"
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		panic(err)
	}

	// Convert the data to a byte slice ([]byte)
	byteData := []byte(data)
	cert, err := loadCert(byteData)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(byteData))

	verifier2, err := signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to load signature from certificate: %w", err)
	}

	cosignVeriOptions := cosign.CheckOpts{
		Identities:   identities,
		RekorPubKeys: trustedTransparencyLogPubKeys,
		SigVerifier:  verifier2,
	}

	fmt.Println("Started the verification")

	verified_signatures, isVerified, err := cosign.VerifyImageSignatures(ctx, ref, &cosignVeriOptions)
	fmt.Println("-----------------------------Signature verification in Progress -------------------------------")
	if err != nil {
		fmt.Println("No signature matched : ")
	}

	if !isVerified {
		fmt.Println("---------------------------------Verification failed ----------------------------------------")
	}

	fmt.Println("")
	fmt.Println("---------------------------- Signature verification completed  ----------------------------------")
	return verified_signatures, err

}

func cosign2() {
	// regstry := os.Getenv("REGISTRY")
	// repo := os.Getenv("REPOSITORY")
	// identity := os.Getenv("DIGEST")
	// image := regstry + "/" + repo + "@" + identity
	// image := os.Getenv("IMAGE_URI")
	// fmt.Println(image)
	image := "ghcr.io/hackeramitkumar/client:unverified"
	ref, err := name.ParseReference(image)
	if err != nil {
		panic(err)
	}

	fmt.Println("--------------------------------  Image refrence information : ------------------------------")
	fmt.Println("Registry : ", ref.Context().RegistryStr())
	fmt.Println("Repository : ", ref.Context().RepositoryStr())
	fmt.Println("Identifier : ", ref.Identifier())

	fmt.Println("")
	fmt.Println("")
	fmt.Println("------------------------------------------Artifacts--------------------------------------------")
	fetchArtifacts(ref)
	fmt.Println()

	fmt.Print("-----------------  Fetching the signedPayload for : ", image)
	fmt.Println("-------------------")
	fmt.Println("")
	fmt.Println("")

	ctx := context.Background()
	signedPayloads, err := cosign.FetchSignaturesForReference(ctx, ref)
	if err != nil {
		fmt.Println("Error During signedPayloads Fetcheing ")
		panic(err)
	}

	fmt.Println("------------------------------------  Fetched all the signedPayloads ----------------------------")
	fmt.Println()

	for _, Payload := range signedPayloads {
		fmt.Println("------------------------------------- Signed Payload Content --------------------------------")
		fmt.Println("")
		fmt.Println("--------------------------------------Signed Payload Bundle  ----------------------------------")

		byteStream, err := json.Marshal(Payload.Bundle)
		if err != nil {
			fmt.Println("Error marshaling JSON:", err)
			return
		}
		jsonString := string(byteStream)
		fmt.Println(jsonString)
		fmt.Println("")

		fmt.Println("--------------------------------------Signature for Payload -----------------------------------")
		fmt.Println(Payload.Base64Signature)
		fmt.Println("")

		fmt.Println("-----------------------------------Certificate for the Payload---------------------------------")
		byteStream2, err := json.Marshal(Payload.Cert)

		if err != nil {
			fmt.Println("Error marshaling JSON:", err)
			return
		}
		jsonString2 := string(byteStream2)
		fmt.Println(jsonString2)
	}

	fmt.Println("")
	fmt.Println("")
	fmt.Println("-------------------------------------Keyed Signature verification --------------------------------------")
	fmt.Println("")

	keyed_verified_signatures, err := keyed_signatureVerification(ctx, ref)
	if err != nil {
		fmt.Println("no signature matched:")
	}
	fmt.Println("")
	fmt.Println("--------------------------------List of the verified signatures ----------------------------------")
	for _, sig := range keyed_verified_signatures {
		fmt.Println(sig.Base64Signature())
	}

	fmt.Println("-------------------------------------Keyless Signature verification --------------------------------------")
	fmt.Println("")

	keyless_verified_signatures, err := keyless_sigantureVerification(ctx, ref)
	if err != nil {
		fmt.Println("no signature matched...")
	}

	fmt.Println("")
	fmt.Println("--------------------------------List of the verified signatures ----------------------------------")
	for _, sig := range keyless_verified_signatures {
		fmt.Println(sig.Base64Signature())
	}
}

func main() {
	cosign2()
}
