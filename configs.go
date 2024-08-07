package aleo_oracle_sdk

import (
	"log"
	"net/http"
)

// CustomBackendConfig is a configuration object for using custom notarizer or verifier.
type CustomBackendConfig struct {
	// Domain name or IP address of the backend
	Address string

	// The port that the backend listens on for the API requests
	Port uint16

	// Whether the client should use HTTPS to connect to the backend
	HTTPS bool

	// Whether the client should resolve the backend (when it's a domain name).
	// If the domain name is resolved to more than one IP, then the requests will be
	// sent to all of the resolved servers, and the first response will be used.
	Resolve bool

	// Optional API prefix to use before the API endpoints
	ApiPrefix string
}

// ClientConfig contains client instantiation configuration.
type ClientConfig struct {
	// NotarizerConfig is a an optional field for configuring the client to use a self-hosted Oracle Notarization service for testing.
	// If not provided, the client will use the default Oracle Notarization service/services hosted by the developer.
	NotarizerConfig *CustomBackendConfig

	// VerifierConfig is a an optional field for configuring the client to use a self-hosted Oracle Notarization Verification service.
	// If not provided, the client will use the default Oracle Notarization Verification service hosted by the developer.
	VerifierConfig *CustomBackendConfig

	// Optional Client logger. No logs will be used if not provided.
	Logger *log.Logger

	// Optional transport configuration. If not provided, the a transport similar to [http.DefaultTransport] will be used.
	Transport http.RoundTripper
}
