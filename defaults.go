package aleo_oracle_sdk

import (
	"time"
)

const (
	// Request timeout used by default for Client's methods
	DEFAULT_TIMEOUT = 5 * time.Second
)

var (
	DEFAULT_NOTARIZATION_OPTIONS = &NotarizationOptions{
		AttestationContext:  nil,
		VerificationContext: nil,
		DataShouldMatch:     true,
		MaxTimeDeviation:    nil,
	}

	DEFAULT_NOTARIZATION_BACKENDS = []*CustomBackendConfig{
		{
			Address:   "sgx.aleooracle.xyz",
			Port:      443,
			HTTPS:     true,
			ApiPrefix: "",
			Resolve:   true,
		},
		{
			Address:   "nitro.aleooracle.xyz",
			Port:      443,
			HTTPS:     true,
			ApiPrefix: "",
			Resolve:   true,
		},
	}

	DEFAULT_VERIFICATION_BACKEND = &CustomBackendConfig{
		Address:   "verifier.aleooracle.xyz",
		Port:      443,
		HTTPS:     true,
		ApiPrefix: "",
		Resolve:   true,
	}
)
