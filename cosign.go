package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	// "k8s.io/client-go/tools/reference"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
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

	// desc, err := remote.Get(ref)
	// if err != nil {
	// 	panic(err)
	// }

	// byteStream, err := json.Marshal(desc.Descriptor)
	// if err != nil {
	// 	fmt.Println("error during the marshaling of descriptor")
	// 	panic(err)
	// }
	// jsonString := string(byteStream)
	// fmt.Println(jsonString)

	// img, err := remote.Image(ref)
	// if err != nil {
	// 	panic(err)
	// }
	// manifest, err := img.Manifest()
	// if err != nil {
	// 	panic(err)
	// }
	// byteStream3, err := json.Marshal(manifest)
	// if err != nil {
	// 	panic(err)
	// }
	// jsonString3 := string(byteStream3)
	// fmt.Println("manifest :", jsonString3)
	// desct := v1ToOciSpecDescriptor(descriptor)
	manifestBytes, err := crane.Manifest(ref.String())
	if err != nil {
		panic(err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		panic(err)
	}

	predicateRef := ref.Context().RegistryStr() + "/" + ref.Context().RepositoryStr() + "@" + manifest.Layers[0].Digest.String()
	layer, err := crane.PullLayer(predicateRef)
	if err != nil {
		panic(err)
	}

	io, err := layer.Uncompressed()
	if err != nil {
		panic(err)
	}
	buf := new(bytes.Buffer)

	_, err = buf.ReadFrom(io)
	if err != nil {
		panic(err)
	}

	fmt.Println(buf.String())

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

	identity := cosign.Identity{
		Issuer:  "https://accounts.google.com",
		Subject: "amit9116260192@gmail.com",
	}

	identities := []cosign.Identity{
		identity,
	}

	trustedTransparencyLogPubKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		fmt.Println("Error occured during the getting rekor pubs keys...")
	}
	fmt.Println("Rekor keys are : ", trustedTransparencyLogPubKeys.Keys)

	// filePath := "demo.txt"
	// data, err := ioutil.ReadFile(filePath)
	// if err != nil {
	// 	fmt.Println("Error reading file:", err)
	// 	panic(err)
	// }

	// // Convert the data to a byte slice ([]byte)
	// byteData := []byte(data)
	// cert, err := loadCert(byteData)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Println(string(byteData))

	// verifier2, err := signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to load signature from certificate: %w", err)
	// }

	roots, err := fulcio.GetRoots()
	if err != nil {
		fmt.Println("Did not get roots")
	}

	// rekorUrl := "https://rekor.sigstore.dev"

	// rekor_client, err := rekor.NewClient(rekorUrl)
	ctLogPubKeys, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		fmt.Println("Error with CTLogPubKeys")
	}

	cosignOptions := cosign.CheckOpts{
		Identities:   identities,
		RekorPubKeys: trustedTransparencyLogPubKeys,
		CTLogPubKeys: ctLogPubKeys,
		RootCerts:    roots,
	}

	verified_signatures, isVerified, err := cosign.VerifyImageSignatures(ctx, ref, &cosignOptions)
	fmt.Println("-----------------------------Signature verification in Progress -------------------------------")
	if err != nil {
		fmt.Println("No signature matched : ", err)
		return nil, nil
	}

	if !isVerified {
		fmt.Println("---------------------------------Verification failed ----------------------------------------")
		return nil, nil
	}

	fmt.Println("")
	fmt.Println("---------------------------- Signature verification completed  ----------------------------------")
	return verified_signatures, err
}

func v1ToOciSpecDescriptor(v1desc v1.Descriptor) ocispec.Descriptor {
	ociDesc := ocispec.Descriptor{
		MediaType:   string(v1desc.MediaType),
		Digest:      digest.Digest(v1desc.Digest.String()),
		Size:        v1desc.Size,
		URLs:        v1desc.URLs,
		Annotations: v1desc.Annotations,
		Data:        v1desc.Data,

		ArtifactType: v1desc.ArtifactType,
	}
	if v1desc.Platform != nil {
		ociDesc.Platform = &ocispec.Platform{
			Architecture: v1desc.Platform.Architecture,
			OS:           v1desc.Platform.OS,
			OSVersion:    v1desc.Platform.OSVersion,
		}
	}
	return ociDesc
}

func extractPayload(verified []oci.Signature) ([]payload.SimpleContainerImage, error) {
	var sigPayloads []payload.SimpleContainerImage
	for _, sig := range verified {
		pld, err := sig.Payload()
		if err != nil {
			return nil, fmt.Errorf("failed to get payload: %w", err)
		}

		sci := payload.SimpleContainerImage{}
		if err := json.Unmarshal(pld, &sci); err != nil {
			return nil, fmt.Errorf("error decoding the payload: %w", err)
		}

		sigPayloads = append(sigPayloads, sci)
	}
	return sigPayloads, nil
}

func verifyAttestaions(ctx context.Context, ref name.Reference, predicateType string) ([]oci.Signature, error) {
	identity := cosign.Identity{
		Issuer:  "https://accounts.google.com",
		Subject: "amit9116260192@gmail.com",
	}

	identities := []cosign.Identity{
		identity,
	}

	trustedTransparencyLogPubKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		fmt.Println("Error occured during the getting rekor pubs keys...")
	}
	fmt.Println("Rekor keys are : ", trustedTransparencyLogPubKeys.Keys)

	ctLogPubKeys, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		fmt.Println("Error with CTLogPubKeys")
	}

	roots, err := fulcio.GetRoots()
	if err != nil {
		fmt.Println("Did not get roots")
	}

	cosignOptions := cosign.CheckOpts{
		Identities:   identities,
		RekorPubKeys: trustedTransparencyLogPubKeys,
		CTLogPubKeys: ctLogPubKeys,
		RootCerts:    roots,
	}

	sigs, bundelVerified, err := cosign.VerifyImageSignatures(ctx, ref, &cosignOptions)

	if err != nil {
		fmt.Println("Error in fething verified siganture", err)
	}
	if !bundelVerified {
		fmt.Println("Bundle is not verified!!", err)
	}

	for _, sig := range sigs {

	}

}

func fetch_attestations(ctx context.Context, repo string) {
	// image := "ghcr.io/hackeramitkumar/client:unverified"

	ref, err := name.ParseReference(repo)
	if err != nil {
		panic(err)
	}

	// img, err := remote.Image(ref)
	desc, err := crane.Head(repo)
	//
	//
	if err != nil {
		fmt.Println("error in Crane.Head call")
	}

	refDescs, err := remote.Referrers(ref.Context().Digest(desc.Digest.String()))
	if err != nil {
		fmt.Println("error in refferels api : ", ref.Context().Digest(desc.Digest.String()))
		panic(err)
	}
	fmt.Println("---------------------------Fetching the referrers-----------------------------------")
	fmt.Println()
	// fmt.Println("Data :", str2)
	for _, descriptor := range refDescs.Manifests {
		fmt.Println("Digest:", descriptor.Digest.String())
		fmt.Println("Artifact Type:", descriptor.ArtifactType)

		if descriptor.ArtifactType == "application/spdx+json" {
			ref := ref.Context().RegistryStr() + "/" + ref.Context().RepositoryStr() + "@" + descriptor.Digest.String()
			reference, err := name.ParseReference(ref)
			if err != nil {
				panic(err)
			}

			// desct := v1ToOciSpecDescriptor(descriptor)
			manifestBytes, err := crane.Manifest(ref)
			if err != nil {
				panic(err)
			}

			var manifest ocispec.Manifest
			if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
				panic(err)
			}

			predicateRef := reference.Context().RegistryStr() + "/" + reference.Context().RepositoryStr() + "@" + manifest.Layers[0].Digest.String()
			layer, err := crane.PullLayer(predicateRef)
			if err != nil {
				panic(err)
			}

			io, err := layer.Uncompressed()
			if err != nil {
				panic(err)
			}
			buf := new(bytes.Buffer)

			_, err = buf.ReadFrom(io)
			if err != nil {
				panic(err)
			}

			fmt.Println(buf.String())
		}
	}

}

func cosign2(ctx context.Context, image string) {
	// regstry := os.Getenv("REGISTRY")
	// repo := os.Getenv("REPOSITORY")
	// identity := os.Getenv("DIGEST")
	// image := regstry + "/" + repo + "@" + identity
	// image := os.Getenv("IMAGE_URI")
	// fmt.Println(image)
	// image := "ghcr.io/hackeramitkumar/client:unverified"
	ref, err := name.ParseReference(image)
	if err != nil {
		panic(err)
	}

	fmt.Println("--------------------------------  Image refrence information : ------------------------------")
	fmt.Println("Registry : ", ref.Context().RegistryStr())
	fmt.Println("Repository : ", ref.Context().RepositoryStr())
	fmt.Println("Identifier : ", ref.Identifier())

	fmt.Println("")
	fmt.Println("------------------------------------------Artifacts--------------------------------------------")
	fetchArtifacts(ref)
	fmt.Println()

	fmt.Print("-----------------  Fetching the signedPayload for : ", image)
	fmt.Println("-------------------")
	fmt.Println("")
	fmt.Println("")

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

	ctx := context.Background()
	image := "localhost:5001/demo-reffer:app3"

	// cosign2(ctx, image)

	fmt.Println("--------------------------------------------Fetch attestation-------------------------------------")

	fetch_attestations(ctx, image)
}
