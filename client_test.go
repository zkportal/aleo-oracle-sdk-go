package oracle

import (
	"context"
	"log"
	"net/http"
)

func Example() {
	// First, we configure the client
	config := &ClientConfig{
		NotarizerConfig: &CustomBackendConfig{
			URL: "https://sgx.aleooracle.xyz",
		},
		VerifierConfig: &CustomBackendConfig{
			URL: "https://verifier.aleooracle.xyz",
		},
		Logger: log.Default(),
	}

	// Create a client
	client, err := NewClient(config)
	if err != nil {
		log.Fatalln(err)
	}

	// Fetch enclave info for all attesters
	infoList, errList := client.GetEnclavesInfo(nil)
	if errList != nil {
		log.Fatalln(errList)
	}

	for _, info := range infoList {
		log.Println()
		log.Println("Enclave info:", info, info.SgxInfo)
		log.Println()
	}

	// Build attestation request
	req := &AttestationRequest{
		URL:            "archive-api.open-meteo.com/v1/archive?latitude=38.9072&longitude=77.0369&start_date=2023-11-20&end_date=2023-11-21&daily=rain_sum",
		ResponseFormat: "json",
		RequestMethod:  http.MethodGet,
		Selector:       "daily.rain_sum.[0]",
		EncodingOptions: EncodingOptions{
			Value:     "float",
			Precision: 2,
		},
	}

	// Use TestSelector in development if you need to figure out what kind of response you're getting from the attestation target
	responses, errList := client.TestSelector(req, nil)
	if errList != nil {
		log.Fatalln(errList)
	}

	log.Println()
	log.Println("Test selector result:", *responses[0])
	log.Println()

	// Use attested notarization once you've figured out what request options you want
	timeDeviation := int64(500) // 500ms
	options := &NotarizationOptions{
		AttestationContext:  context.Background(),
		VerificationContext: context.Background(),
		DataShouldMatch:     true,
		MaxTimeDeviation:    &timeDeviation,
	}

	attestations, errList := client.Notarize(req, options)
	if errList != nil {
		log.Fatalln(errList)
	}

	// The URL was notarized, the extracted result was attested by the enclaves, enclave signatures were verified by the verifier, you can now use the data
	log.Println()
	log.Println("Data extracted from the URL using the selector:", attestations[0].AttestationData)
	log.Println()

	log.Println()
	log.Println("Attestation response prepared for using in an Aleo contract:", attestations[0].OracleData.UserData)
	log.Println()

	// Output:
}
