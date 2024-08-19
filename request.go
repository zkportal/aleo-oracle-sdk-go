package aleo_oracle_sdk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type oracleError struct {
	Message            string `json:"errorMessage"`
	Code               uint   `json:"errorCode"`
	Details            string `json:"errorDetails"`
	ResponseStatusCode int    `json:"responseStatusCode"`
}

type requestContext struct {
	Ctx       context.Context
	Method    string
	Transport http.RoundTripper
	Backend   *CustomBackendConfig
}

// Builds a URL using the backend information, path, and optionally resolved IP address.
// Do not use with queries, they will be escaped
func getFullAddress(path string, queryParams map[string]string, backend *CustomBackendConfig, ip *string) string {
	full := new(url.URL)

	if queryParams != nil {
		query := make(url.Values)
		for key, val := range queryParams {
			query.Set(key, val)
		}
		full.RawQuery = query.Encode()
	}

	if backend.HTTPS {
		full.Scheme = "https"
		if backend.Port == 0 {
			backend.Port = 443
		}
	} else {
		full.Scheme = "http"
		if backend.Port == 0 {
			backend.Port = 80
		}
	}

	// if we're using an IP address, we always add the port.
	// if we're not, then add the port only if it's not standard for the scheme
	if ip == nil {
		full.Host = backend.Address
		if (backend.HTTPS && backend.Port != 443) || (!backend.HTTPS && backend.Port != 80) {
			full.Host = fmt.Sprintf("%s:%d", backend.Address, backend.Port)
		}
	} else {
		full.Host = fmt.Sprintf("%s:%d", *ip, backend.Port)
	}

	full.Path, _ = url.JoinPath(backend.ApiPrefix, path)

	return full.String()
}

func constructHttpRequest(ctx *requestContext, path string, queryParams map[string]string, ip *string, reqBody []byte) (*http.Request, error) {
	httpReq := new(http.Request)
	var err error

	reqUrl := getFullAddress(path, queryParams, ctx.Backend, ip)

	if ctx.Method == http.MethodGet {
		httpReq, err = http.NewRequestWithContext(ctx.Ctx, ctx.Method, reqUrl, nil)
		if err != nil {
			return nil, err
		}
	} else if ctx.Method == http.MethodPost {
		httpReq, err = http.NewRequestWithContext(ctx.Ctx, ctx.Method, reqUrl, bytes.NewBuffer(reqBody))
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("HTTP method not allowed")
	}

	httpReq.Header.Set("Content-Type", "application/json")

	return httpReq, nil
}

func executeRequestInternal[ResponseType interface{}](ctx context.Context, req *http.Request, client *http.Client, wg *sync.WaitGroup, resChan chan *ResponseType, errChan chan error) {
	defer wg.Done()

	respObj, err := client.Do(req)
	if err != nil {
		errChan <- fmt.Errorf("failed to execute request: %w", err)
		return
	}

	// check if cancelled
	select {
	case <-ctx.Done():
		return
	default:
	}

	body, err := io.ReadAll(respObj.Body)
	if err != nil {
		errChan <- fmt.Errorf("failed to read response body: %w", err)
		return
	}
	defer respObj.Body.Close()

	resp := new(ResponseType)
	respError := new(oracleError)

	// check if cancelled
	select {
	case <-ctx.Done():
		return
	default:
	}

	// decode as an error first since we know the exact type and can check if it's the error response or success response
	err = json.Unmarshal(body, respError)
	if err != nil {
		// it's a marshalling error and not an API error
		errChan <- fmt.Errorf("failed to decode response: %w", err)
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

		errChan <- errors.New(apiErrorStr)
		return
	}

	// if there's no error message, and the status code is not 200, something went really wrong, e.g. at the routing/balancing level.
	// note that this is different from the resp.ResponseStatusCode in AttestationResponse and TestSelectorResponse since it's the response status code
	// of the attestation target.
	if respObj.StatusCode != 200 {
		errChan <- fmt.Errorf("request failed: %s", respObj.Status)
		return
	}

	// check if cancelled
	select {
	case <-ctx.Done():
		return
	default:
	}

	// there's no error message, test if it's a successful response
	err = json.Unmarshal(body, resp)
	if err != nil {
		// it's a marshalling error and not an API error
		errChan <- fmt.Errorf("failed to decode response: %w", err)
		return
	}

	// check if cancelled
	select {
	case <-ctx.Done():
	case resChan <- resp:
	}
}

// creates an HTTP request of provided method (can be only GET or POST) to the provided URL, with an optional body of RequestType,
// then executes the requests, parses the body as ResponseType if the response was successful, or reports an error.
// All results are returned using channels, completion is indicated using a wait group.
//
// Sets "Content-Type: application/json" header for all requests. Non-2xx status code is handled as an error. The body may contain an
// error object, which is returned in errChan when possible.
func executeRequest[RequestType interface{}, ResponseType interface{}](path string, queryParams map[string]string, ctx *requestContext, req *RequestType, wg *sync.WaitGroup, resChan chan *ResponseType, errChan chan error) {
	defer wg.Done()

	var err error

	host := getFullAddress("", nil, ctx.Backend, nil)
	basicRequestErr := errors.New(getFullAddress(path, queryParams, ctx.Backend, nil))

	var resolvedAddresses []string
	resolved := false

	if ctx.Backend.Resolve {
		resolvedAddresses, err = resolveIPv4(ctx.Backend.Address)
		if err != nil {
			errChan <- fmt.Errorf("executeRequest: failed to lookup %s: %w", host, err)
			return
		}
		resolved = true
	} else {
		resolvedAddresses = []string{ctx.Backend.Address}
	}

	transport := ctx.Transport

	// the infrastructure uses SNI for routing. since we looked up the hostname
	// and we want to send requests to all IPs, we have to use the addresses for request.
	// this also means we have to set the servername in the TLS config for SNI.
	transportRaw := transport.(*http.Transport)
	if transportRaw.TLSClientConfig == nil {
		transportRaw.TLSClientConfig = &tls.Config{}
	}

	// Set SNI for routing
	transportRaw.TLSClientConfig.ServerName = ctx.Backend.Address
	// Since our infrastructure performs routing on TCP level to the notarizer, which then upgrades
	// protocol to HTTP, changing the SNI to verifier.aleooracle.xyz doesn't actually reroute us to the verifier
	// because we're stuck in the notarizer's HTTP connection. Disabling HTTP "keep alive"s allows the proxy
	// to escape the notarizer's HTTP connection and route again on TCP level to the verifier's HTTP server.
	// This wasn't relevant when resolving was disabled for the verifier.
	transportRaw.DisableKeepAlives = true

	transport = transportRaw

	// common client to use for all resolved IP addresses. it has the SNI already configured
	client := &http.Client{
		Transport: transport,
	}

	// we do the same request for all servers therefore we can serialize the request body (if exists) once
	// before building the request
	var reqBody []byte
	if ctx.Method == http.MethodPost && req != nil {
		reqBody, err = json.Marshal(req)
		if err != nil {
			errChan <- fmt.Errorf("executeRequest: failed to marshal request for %s: %w", host, err)
			return
		}
	}

	// send concurrent requests for every resolved host, taking in the first successful result, not caring about
	// the rest
	wgInternal := new(sync.WaitGroup)
	successInternalCh := make(chan *ResponseType, 1)
	errorsInternalCh := make(chan error, len(resolvedAddresses))

	// separate context for cancelling
	ctxInternal, cancel := context.WithCancel(ctx.Ctx)
	defer cancel()

	internalCtx := &requestContext{
		Ctx:       ctxInternal,
		Backend:   ctx.Backend,
		Method:    ctx.Method,
		Transport: transport,
	}

	for _, address := range resolvedAddresses {
		// if we used hostname resolving, then we supply the address as an IP argument
		var usedIp *string = nil
		if resolved {
			usedIp = &address
		}

		httpReq, err := constructHttpRequest(internalCtx, path, queryParams, usedIp, reqBody)
		if err != nil {
			errChan <- fmt.Errorf("executeRequest: failed to create a request for %w: %w", basicRequestErr, err)
			return
		}

		wgInternal.Add(1)
		go executeRequestInternal[ResponseType](ctxInternal, httpReq, client, wgInternal, successInternalCh, errorsInternalCh)
	}

	go func() {
		wgInternal.Wait()
		close(successInternalCh)
		close(errorsInternalCh)
	}()

	var res *ResponseType
	var ok bool
	// read the results of the requests to all hosts. we should have the first successful one in the success channel.
	// if it's empty, we read the errors channel and return all of them

	res, ok = <-successInternalCh
	// cancel the rest of the requests as soon as we get our first result
	if ok {
		cancel()
		resChan <- res
		return
	}

	// forward errors to the external channel
	// collect all unique errors, join them with ; and return as one error
	errMap := make(map[error]bool)

	for err := range errorsInternalCh {
		errMap[err] = true
	}

	errList := make([]string, 0, len(errMap))
	for err := range errMap {
		errList = append(errList, fmt.Sprintf("executeRequest: %s: %s", basicRequestErr, err))
	}

	errChan <- fmt.Errorf("%s", strings.Join(errList, "; "))
}
