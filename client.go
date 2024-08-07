package aleo_oracle_sdk

import (
	"log"
	"net"
	"net/http"
	"time"
)

const (
	REPORT_TYPE_SGX = "sgx"
)

// Aleo Oracle client.
type Client struct {
	notarizer []*CustomBackendConfig
	verifier  *CustomBackendConfig
	logger    *log.Logger
	transport http.RoundTripper
}

// NewClient creates a new client using the provided configuration. Configuration is optional.
// If configuration is not provided, will use 1 notarizer and a verifier hosted by the developers,
// no logging, a transport similar to [http.DefaultTransport] for transport.
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

	// Use the configured notarizer backend.
	// Use default notarization backends if the configuration is missing.
	// Note that the configuration allows configuring only one backend, while the SDK supports multiple
	// notarization backends.
	if config.NotarizerConfig != nil {
		client.notarizer = make([]*CustomBackendConfig, 1)
		client.notarizer[0] = config.NotarizerConfig
		client.logger.Println("Oracle Client: using custom notarizer -", getFullAddress("", config.NotarizerConfig, nil))
	} else {
		client.notarizer = DEFAULT_NOTARIZATION_BACKENDS
	}

	// Use the configured verification backend.
	// Use default verification backend if the configuration is missing.
	if config.VerifierConfig != nil {
		client.verifier = config.VerifierConfig
		client.logger.Println("Oracle Client: using custom verifier -", getFullAddress("", config.VerifierConfig, nil))
	} else {
		client.verifier = DEFAULT_VERIFICATION_BACKEND
	}

	if config.Transport != nil {
		client.transport = config.Transport
	} else {
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		client.transport = &http.Transport{
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	return client, nil
}
