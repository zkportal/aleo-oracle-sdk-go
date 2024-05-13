package oracle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
)

type oracleError struct {
	Message            string `json:"errorMessage"`
	Code               uint   `json:"errorCode"`
	Details            string `json:"errorDetails"`
	ResponseStatusCode int    `json:"responseStatusCode"`
}

// creates an HTTP request of provided method (can be only GET or POST) to the provided URL, with an optional body of RequestType,
// then executes the requests, parses the body as ResponseType if the response was successful, or reports an error.
// All results are returned using channels, completion is indicated using a wait group.
//
// Sets "Content-Type: application/json" header for all requests. Non-2xx status code is handled as an error. The body may contain an
// error object, which is returned in errChan when possible.
func executeRequest[RequestType interface{}, ResponseType interface{}](wg *sync.WaitGroup, resChan chan *ResponseType, errChan chan error, client *http.Client, ctx context.Context, method string, url string, req *RequestType) {
	defer wg.Done()

	var httpReq *http.Request
	var err error

	if method == http.MethodGet {
		httpReq, err = http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			errChan <- fmt.Errorf("executeRequest: %w: %w", errors.New(url), err)
			return
		}
	} else if method == http.MethodPost {
		reqBody, err := json.Marshal(req)
		if err != nil {
			errChan <- fmt.Errorf("executeRequest: %w: %w", errors.New(url), err)
			return
		}

		httpReq, err = http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(reqBody))
		if err != nil {
			errChan <- fmt.Errorf("executeRequest: %w: %w", errors.New(url), err)
			return
		}
	} else {
		errChan <- fmt.Errorf("executeRequest: %w HTTP method not allowed", errors.New(url))
		return
	}

	httpReq.Header.Set("Content-Type", "application/json")

	respObj, err := client.Do(httpReq)
	if err != nil {
		errChan <- fmt.Errorf("executeRequest: %w: %w", errors.New(url), err)
		return
	}

	body, err := io.ReadAll(respObj.Body)
	if err != nil {
		errChan <- fmt.Errorf("executeRequest: %w: %w", errors.New(url), err)
		return
	}
	defer respObj.Body.Close()

	resp := new(ResponseType)
	respError := new(oracleError)

	// decode as an error first since we know the exact type and can check if it's the error response or success response
	err = json.Unmarshal(body, respError)
	if err != nil {
		// it's a marshalling error and not an API error
		errChan <- fmt.Errorf("executeRequest: %w: %w", errors.New(url), err)
		return
	}

	// check if this is an API error, expose it to the client
	if respError.Message != "" {
		apiErrorStr := respError.Message

		if respError.ResponseStatusCode != 0 {
			apiErrorStr += ", target responded with HTTP " + fmt.Sprint(respError.ResponseStatusCode)
		}

		if respError.Details != "" {
			apiErrorStr += ", details - " + respError.Details
		}

		errChan <- fmt.Errorf("executeRequest: %w: %w", errors.New(url), errors.New(apiErrorStr))
		return
	}

	// if there's no error message, and the status code is not 200, something went really wrong, e.g. at the routing/balancing level.
	// note that this is different from the resp.ResponseStatusCode in AttestationResponse and TestSelectorResponse since it's the response status code
	// of the attestation target.
	if respObj.StatusCode != 200 {
		errChan <- fmt.Errorf("executeRequest: %w: %w", errors.New(url), fmt.Errorf("request failed: %s", respObj.Status))
		return
	}

	// there's no error message, test if it's a successful response
	err = json.Unmarshal(body, resp)
	if err != nil {
		// it's a marshalling error and not an API error
		errChan <- fmt.Errorf("executeRequest: %w: %w", errors.New(url), err)
		return
	}

	resChan <- resp
}
