package aleo_oracle_sdk

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
)

// Requests an attested random number within a [0, max) interval.
func (c *Client) GetAttestedRandom(max *big.Int, options *NotarizationOptions) ([]*AttestationResponse, []error) {
	// compute 2^27 as an upper bound for the random
	maxAllowed := big.NewInt(2)
	maxAllowed = maxAllowed.Lsh(maxAllowed, 127)

	if max.Sign() <= 0 || max.Cmp(big.NewInt(1)) == 0 || max.Cmp(maxAllowed) == 1 {
		return nil, []error{errors.New("invalid upper bound for random")}
	}

	// configure default options
	if options == nil {
		options = DEFAULT_NOTARIZATION_OPTIONS
		// default notarization options require the notarized data to match, which is not possible with the random number
		options.DataShouldMatch = false
	}

	// configure default attestation timeout context
	if options.AttestationContext == nil {
		ctx, cancel := context.WithTimeout(context.Background(), DEFAULT_TIMEOUT)
		defer cancel()

		options.AttestationContext = ctx
	}

	numServices := len(c.notarizer)

	var wg sync.WaitGroup
	wg.Add(numServices)

	resChanMap := make(map[string]chan *AttestationResponse, numServices)
	errChan := make(chan error, numServices)

	for _, serviceConfig := range c.notarizer {
		resChanMap[serviceConfig.Address] = make(chan *AttestationResponse, 1)
		go executeRequest[any](
			"/random",
			map[string]string{"max": max.String()},
			&requestContext{Ctx: options.AttestationContext, Method: http.MethodGet, Backend: serviceConfig, Transport: c.transport},
			nil,
			&wg,
			resChanMap[serviceConfig.Address],
			errChan,
		)
	}

	wg.Wait()
	for _, ch := range resChanMap {
		close(ch)
	}
	close(errChan)

	// one or more of the requests have failed
	if len(errChan) > 0 {
		var reqErrors []error
		for err := range errChan {
			reqErrors = append(reqErrors, err)
			c.logger.Println("failed to create attestation:", err)
		}

		// all request have failed
		if len(reqErrors) == numServices {
			return nil, reqErrors
		}
	}

	var attestations []*AttestationResponse
	for enclaveUrl, resChan := range resChanMap {
		resp := <-resChan
		resp.EnclaveUrl = enclaveUrl
		attestations = append(attestations, resp)
	}

	c.logger.Printf("Notarize: notarized and attested random number using %d attesters", len(c.notarizer))

	err := c.handleAttestations(attestations, options)
	if err != nil {
		return nil, []error{err}
	}

	// configure default verification timeout context
	if options.VerificationContext == nil {
		ctx, cancel := context.WithTimeout(context.Background(), DEFAULT_TIMEOUT)
		defer cancel()

		options.VerificationContext = ctx
	}

	validAttestations, err := c.verifyReports(options.VerificationContext, attestations)
	if err != nil {
		return nil, []error{fmt.Errorf("attestation report verification failed: %w", err)}
	}

	c.logger.Println("Attestations verified by", getFullAddress("", nil, c.verifier, nil))

	return validAttestations, nil
}
