package oracle

import (
	"log"
	"net/http"
	"net/url"
	"time"
)

const (
	// Request timeout used by default for Client's methods
	DEFAULT_TIMEOUT = 5 * time.Second

	REPORT_TYPE_SGX = "sgx"
)

// CustomBackendConfig is a configuration object for using custom notarizer or verifier.
type CustomBackendConfig struct {
	// Base URL of the backend, e.g. https://backend.example.com:8080.
	URL string
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

	// Optional transport configuration. If not provided, the [http.DefaultTransport] will be used.
	Transport http.RoundTripper
}

// Aleo Oracle client.
type Client struct {
	notarizer []*CustomBackendConfig
	verifier  *CustomBackendConfig
	logger    *log.Logger
	client    *http.Client
}

// NewClient creates a new client using the provided configuration. Configuration is optional.
// If configuration is not provided, will use 1 notarizer and a verifier hosted by the developers, no logging, [http.DefaultTransport] for transport.
func NewClient(config *ClientConfig) (*Client, error) {
	client := new(Client)

	if config == nil {
		config = new(ClientConfig)
	}

	if config.Logger != nil {
		client.logger = config.Logger
	} else {
		client.logger = noopLogger
	}

	if config.NotarizerConfig == nil {
		client.notarizer = []*CustomBackendConfig{
			{URL: "https://sgx.aleooracle.xyz"},
		}
	} else {
		// sanity check the URL
		_, err := url.Parse(config.NotarizerConfig.URL)
		if err != nil {
			return nil, err
		}
		client.notarizer = make([]*CustomBackendConfig, 1)
		client.notarizer[0] = config.NotarizerConfig
		client.logger.Println("Oracle Client: using custom notarizer -", config.NotarizerConfig.URL)
	}

	if config.VerifierConfig == nil {
		client.verifier = &CustomBackendConfig{
			URL: "https://verifier.aleooracle.xyz",
		}
	} else {
		// sanity check the URL
		_, err := url.Parse(config.VerifierConfig.URL)
		if err != nil {
			return nil, err
		}
		client.verifier = config.VerifierConfig
		client.logger.Println("Oracle Client: using custom verifier -", config.VerifierConfig.URL)
	}

	client.client = new(http.Client)

	if config.Transport != nil {
		client.client.Transport = config.Transport
	} else {
		client.client.Transport = http.DefaultTransport
	}

	return client, nil
}
