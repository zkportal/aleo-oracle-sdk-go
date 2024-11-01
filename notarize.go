// This package provides a client for Aleo Oracle.
//
// This client is for developing applications that need to consume data trustlessly from an HTTPS source and securely express them in Web3.
//
// Oracles provide a way for the decentralized Web3 ecosystem to access existing data sources, legacy systems, and advanced computations, but come with a downside
// of having to trust the oracle owner. Unlike them, Aleo Oracle is trustless and doesn't have an owner, thus solving the problem.
//
// This SDK can be used with an Aleo oracle contract to expose data to Aleo blockchain in a trustless way using [TEEs (Trusted Execution Environment)] like [Intel SGX] and [Aleo's SnarkVM].
//
// Most of the heavy lifting is done on the backend side, where one or more instances of [notarization backends] create
// attestations on requested data, which can be [verified locally and remotely], and in a contract.
//
// # Terms
//
// TEE - Trusted Execution Environment - is an area on the main processor of a device that is separated from the system's main operating system. It ensures data is stored, processed and protected in a secure environment.
//
// Attestation Report - A document that confirms the enclave is running a particular piece of code or specific container.
//
// Notarization Backend - Oracle Backend that is running in TEE. This backend makes a request to the Attestation Target, extracts data from the response and creates an Attestation Report, which includes data and how this data was obtained.
//
// Verification Backend - Backend that is verifying that an Attestation Report is valid and has not been modified.
//
// Attestation Target - A remote server which provides data that you want to notarize. For example, an exchange with currency rates.
//
// Attestation Response - A response containing the data required for notarization that backend gets when it requests an Attestation Target with the provided Attestation Request.
//
// Attestation Request - Information on how to reproduce the requests to an Attestation Target. From URL and request method to all of the request headers.
//
// Attestation Data - Data extracted from an Attestation Response, that you want to notarize. For example, BTC to USDT exchange rate.
//
// [TEEs (Trusted Execution Environment)]: https://en.wikipedia.org/wiki/Trusted_execution_environment
// [Intel SGX]: https://www.intel.com/content/www/us/en/architecture-and-technology/software-guard-extensions.html
// [Aleo's SnarkVM]: https://developer.aleo.org/aleo
// [notarization backends]: https://github.com/summitto/oracle-notarization-backend
// [verified locally and remotely]: https://github.com/summitto/oracle-verification-backend
package aleo_oracle_sdk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
)

// The expected type of value that should be used to interpret Attestation Data to encode it to Aleo format (to be used in an Aleo program).
type EncodingOptionsValueType string

// Available options for EncodingOptionsValueType
const (
	ENCODING_OPTIONS_VALUE_STRING EncodingOptionsValueType = "string" // Extracted value is interpretted as a string
	ENCODING_OPTIONS_VALUE_FLOAT  EncodingOptionsValueType = "float"  // Extracted value is interpreted as a positive floating point number up to 64 bits in size
	ENCODING_OPTIONS_VALUE_INT    EncodingOptionsValueType = "int"    // Extracted value is interpreted as an unsigned decimal integer up to 64 bits in size
)

var (
	// Default headers that will be added to the attestation request.
	DEFAULT_NOTARIZATION_HEADERS = map[string]string{
		"Accept":                    "*/*",
		"User-Agent":                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Upgrade-Insecure-Requests": "1",
		"DNT":                       "1",
	}
)

// EncodingOptions is a type containing information about how Notarization Backend should interpret the Attestation Data to encode it to Aleo format.
// Data will be encoded to Aleo "u128" to allow for usage inside of Aleo programs.
type EncodingOptions struct {
	// Defines how Notarization Backend should interpret the Attestation Data to encode it to Aleo format.
	Value EncodingOptionsValueType

	// Aleo program encoding precision of the Attestation Data when interpreting as float and encoding it to Aleo format.
	// Must be equal or bigger than the number of digits after the comma. Maximum is 12.
	//
	// Required if Value is ENCODING_OPTIONS_VALUE_FLOAT
	//
	// Precision should always be bigger or equal to the number of digits in the fractional part of the extracted number.
	// If the number has more digits in the fractional part than the provided precision, it will be sliced to the provided precision.
	//
	// With Precision=3, the slicing examples:
	//   - 123.456 -> 123.456
	//   - 123.45 -> 123.45
	//   - 123.4567 -> 123.456
	//
	// With Precision=0, the slicing examples:
	//   - 123.456 -> 123
	//   - 123.45 -> 123
	//   - 123.4567 -> 123
	Precision int
}

// Attestation target response format
type ResponseFormat string

// Available options for ResponseFormat
const (
	RESPONSE_FORMAT_JSON ResponseFormat = "json"
	RESPONSE_FORMAT_HTML ResponseFormat = "html"
)

// Type of value extraction on a HTML element after applying a selector.
type HtmlResultType string

// Available options for HTML result type.
// Given a selected HTML element
//
//	<a href="/test">Nice link</a>
const (
	HTML_RESULT_TYPE_ELEMENT HtmlResultType = "element" // will extract "<a href="/test">Nice link</a>"
	HTML_RESULT_TYPE_VALUE   HtmlResultType = "value"   // will extract "Nice link"
)

// AttestationRequest contains information about a request to the attestation target, how the attestation target is expected to respond and how to parse its response to extract target data.
//
// IMPORTANT: Max allowed field size is 4kb!
type AttestationRequest struct {
	// URL of a resource to attest - attestation target. Must not include schema - HTTPS is assumed
	URL string `json:"url"`

	// HTTP method to be used for a request to the attestation target. Supports only GET and POST
	RequestMethod string `json:"requestMethod"`

	// Optional element selector for extracting data from the attestation resource - XPath for HTML, JSON key path for JSON.
	// When empty, the oracle attests to the whole response unless the response size limit of **4kb** is hit.
	//
	// JSON key path example - given an example JSON
	// {
	//  "primitive": "value",
	//  "list": [123, 223, 3],
	//  "dictionary": {
	//    "key1": "value1",
	//    "key2": "value2"
	//  }
	// }
	// 	- selector "primitive" will select "value"
	// 	- selector "list.[1]"" will select "223"
	// 	- selector "dictionary.key2" will select "value2".
	Selector string `json:"selector,omitempty"`

	// Expected attestation target response format
	ResponseFormat ResponseFormat `json:"responseFormat"`

	// When ResponseFormat is RESPONSE_FORMAT_HTML, this field indicates the type of extraction
	// for the response after applying the selector.
	HtmlResultType *HtmlResultType `json:"htmlResultType,omitempty"`

	// Information about how to encode Attestation Data to Aleo-compatible format
	EncodingOptions EncodingOptions `json:"encodingOptions"`

	// Can be used to provide a POST request body for the attestation target request.
	//
	// Has effect only when RequestMethod is POST.
	//
	RequestBody *string `json:"requestBody,omitempty"`

	// Can be used to provide a Content-Type request header for the attestation target request.
	//
	// Has effect only when RequestMethod is POST.
	RequestContentType *string `json:"requestContentType,omitempty"`

	// Optional dictionary of HTTP headers to add to the request to attestation target.
	//
	// Value of headers which might contain sensitive information (like "Authorization", "X-Auth-Token" or "Cookie")
	// and any non-standard headers used by attestation target would be replaced with "*****" in attestation report.
	//
	// This SDK will use some default request headers like User-Agent. See DEFAULT_NOTARIZATION_HEADERS.
	//
	RequestHeaders map[string]string `json:"requestHeaders,omitempty"`
}

// NotarizationOptions contains ptional parameters that you can provide to Notarize method.
//
// If not provided, default values will be used.
type NotarizationOptions struct {
	// Optional attestation request context. If not provided, uses a context with timeout of 5s.
	AttestationContext context.Context

	// Optional verification request context. If not provided, uses a context with timeout of 5s.
	VerificationContext context.Context

	// If multiple attesters are used, the client will check that the attestation data is exactly the same in all attestation responses.
	DataShouldMatch bool

	// If multiple attesters are used this option controls the maximum deviation in milliseconds between attestation timestamps.
	//
	// 	- if set to 0, requires that all attestations are done at the same time (not recommended). Note that the attestation timestamp
	// is set by the attestation server using server time.
	// 	- if nil, no time deviation checks are performed.
	//  - if time deviation is set to less then a second, attestation might fail due to naturally occuring network delays between the Oracle SDK, the notarization backends, and the attestation target.
	//  - if deviation is set to more than 10 seconds (10 * 1000 ms), the attestation target responses might differ from each other because one of the requests took too long, and the requested information either has changed or is not available anymore.
	MaxTimeDeviation *int64
}

// PositionInfo contains extra information about the way attestation response was encoded for Aleo. Useful in development to find
// the positions of different response elements for Aleo program development.
type PositionInfo struct {
	// Index of the block where the write operation started. Indexing starts from 0. Note that this number doesn't account the fact that each chunk contains 32 blocks.
	//
	// If Pos is >32, it means that there was an "overflow" to the next chunk of 32 blocks, e.g. Pos 31 means chunk 0 field 31, Pos 32 means chunk 1, field 0.
	Pos int

	// Number of blocks written in the write operation.
	Len int
}

// ProofPositionalInfo is an object containing information about the positions of data included in the Attestation Report hash.
// This object is created to help developers understand how to extract fields to verify or use them in Aleo programs.
//
// No element will occupy positions 0 and 1. Positions 0 and 1 in OracleData.UserData are reserved for information about data positioning, i.e. meta header (which can be used later to decode and verify OracleData.UserData).
type ProofPositionalInfo struct {
	Data            PositionInfo `json:"data"`
	Timestamp       PositionInfo `json:"timestamp"`
	StatusCode      PositionInfo `json:"statusCode"`
	Method          PositionInfo `json:"method"`
	ResponseFormat  PositionInfo `json:"responseFormat"`
	Url             PositionInfo `json:"url"`
	Selector        PositionInfo `json:"selector"`
	EncodingOptions PositionInfo `json:"encodingOptions"`
	RequestHeaders  PositionInfo `json:"requestHeaders"`
	OptionalFields  PositionInfo `json:"optionalFields"` // Optional fields are HTML result type, request content type, request body. They're all encoded together.
}

type NitroReportExtras struct {
	Pcr0Pos     string `json:"pcr0Pos"`
	Pcr1Pos     string `json:"pcr1Pos"`
	Pcr2Pos     string `json:"pcr2Pos"`
	UserDataPos string `json:"userDataPos"`
}

// OracleData contains information that can be used in your Aleo program. All fields are encoded to Aleo-compatible formats and represented as strings.
type OracleData struct {
	// Schnorr signature of a verified Attestation Report.
	Signature string `json:"signature"`

	// Aleo-encoded data that was used to create the hash included in the Attestation Report.
	//
	// See ProofPositionalInfo for an idea of what data goes into the hash.
	UserData string `json:"userData"`

	// Aleo-encoded Attestation Report.
	Report string `json:"report"`

	// Public key the signature was created against.
	Address string `json:"address"`

	// Object containing information about the positions of data included in the Attestation Report hash.
	EncodedPositions ProofPositionalInfo `json:"encodedPositions"`

	// Aleo-encoded request. Same as UserData but with zeroed Data and Timestamp fields. Can be used to validate the request in Aleo programs.
	//
	// Data and Timestamp are the only parts of UserData that can be different every time you do a notarization request.
	// By zeroing out these 2 fields, we can create a constant UserData which is going to represent a request to the attestation target.
	// When an Aleo program is going to verify that a request was done using the correct parameters, like URL, request body, request headers etc.,
	// it can take the UserData provided with the Attestation Report, replace Data and Timestamp with "0u128" and then compare the result with the constant UserData in the program.
	// If both UserDatas match, then we know that the Attestation Report was made using the correct attestation target request!
	//
	// To avoid storing the full UserData in an Aleo program, we can hash it and store only the hash in the program. See RequestHash.
	EncodedRequest string `json:"encodedRequest"`

	// Poseidon8 hash of the EncodedRequest. Can be used to verify in an Aleo program that the report was made with the correct request.
	RequestHash string `json:"requestHash"`

	// Poseidon8 hash of the RequestHash with the attestation timestamp. Can be used to verify in an Aleo program that the report was made with the correct request.
	TimestampedRequestHash string `json:"timestampedRequestHash"`

	// Object containing extra information about the attestation report.
	// If the attestation type is "nitro", it contains Aleo-encoded structs with
	// information that helps to extract user data and PCR values from the report.
	ReportExtras *NitroReportExtras `json:"reportExtras"`
}

// AttestationResponse is notarization backend's response to an attestation request
type AttestationResponse struct {
	// URL of the Notarization Backend the report came from.
	EnclaveUrl string `json:"enclaveUrl"`

	// Attestation Report in Base64 encoding, created by the Trusted Execution Environment using the extracted data.
	AttestationReport string `json:"attestationReport"`

	// Which TEE produced the attestation report. Only Intel SGX is supported at the moment with possibility to have more later.
	ReportType string `json:"reportType"`

	// Data extracted from the attestation target's response using the provided selector. The data is always a string, as seen in the raw HTTP response.
	AttestationData string `json:"attestationData"`

	// Full response body received in the attestation target's response.
	ResponseBody string `json:"responseBody"`

	// Status code of the attestation target's response.
	ResponseStatusCode int `json:"responseStatusCode"`

	// Reserved.
	Nonce string `json:"nonce,omitempty"`

	// Unix timestamp of the attestation date time as seen by the attestation server (not attestation target).
	Timestamp int64 `json:"timestamp"`

	// Information that can be used in your Aleo program, like Aleo-formatted attestation report.
	OracleData OracleData `json:"oracleData"`

	// Original attestation request included in the AttestationReport hash.
	// Keep in mind that all request headers that are not in the list of known headers will be replaced with "*****"".
	// Also the order might be different from the original request (which is important when calculating a hash of AttestationReport).
	AttestationRequest *AttestationRequest `json:"attestationRequest"`
}

// Notarize requests attestation of data extracted from the provided URL using the provided selector. Attestation is created by one or more Trusted Execution Environments (TEE). Returns all successfully produced and verified attestations and discards the invalid ones.
//
// It is highly recommended to use time insensitive historic data for notarization. In case of using live data, other people might see different results when requesting the same url with the same parameters.
//
// Use options to configure attestation. If not provided, will use default options - 5 sec timeouts, DataShouldMatch, no time deviation checks.
func (c *Client) Notarize(req *AttestationRequest, options *NotarizationOptions) ([]*AttestationResponse, []error) {
	// configure default options
	if options == nil {
		options = DEFAULT_NOTARIZATION_OPTIONS
	}

	// configure default attestation timeout context
	if options.AttestationContext == nil {
		ctx, cancel := context.WithTimeout(context.Background(), DEFAULT_TIMEOUT)
		defer cancel()

		options.AttestationContext = ctx
	}

	if req.RequestHeaders == nil {
		req.RequestHeaders = make(map[string]string)
	}

	attestations, errs := c.createAttestation(options.AttestationContext, req)
	if len(errs) > 0 {
		for _, err := range errs {
			c.logger.Println("failed to create attestation:", err)
		}
		return nil, errs
	}
	c.logger.Printf("Notarize: notarized and attested %s using %d attesters", req.URL, len(c.notarizer))

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

type attestationRequestMessage struct {
	AttestationRequest

	DebugRequest bool `json:"debugRequest"`
}

func (c *Client) createAttestation(ctx context.Context, req *AttestationRequest) ([]*AttestationResponse, []error) {
	reqMessage := &attestationRequestMessage{
		AttestationRequest: *req,
		DebugRequest:       false,
	}

	numServices := len(c.notarizer)

	var wg sync.WaitGroup
	wg.Add(numServices)

	resChanMap := make(map[string]chan *AttestationResponse, numServices)
	errChan := make(chan error, numServices)

	// add default notarization headers
	for header, value := range DEFAULT_NOTARIZATION_HEADERS {
		if _, ok := req.RequestHeaders[header]; !ok {
			req.RequestHeaders[header] = value
		}
	}

	for _, serviceConfig := range c.notarizer {
		resChanMap[serviceConfig.Address] = make(chan *AttestationResponse, 1)
		go executeRequest(
			"/notarize",
			nil,
			&requestContext{Ctx: ctx, Method: http.MethodPost, Backend: serviceConfig, Transport: c.transport},
			reqMessage,
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
		}

		// all requests have failed
		if len(reqErrors) == numServices {
			return nil, reqErrors
		}
	}

	var result []*AttestationResponse
	for enclaveUrl, resChan := range resChanMap {
		resp := <-resChan
		if resp != nil {
			resp.EnclaveUrl = enclaveUrl
			result = append(result, resp)
		}
	}

	return result, nil
}

func (c *Client) handleAttestations(attestations []*AttestationResponse, options *NotarizationOptions) error {
	// can't do time deviation and integrity checks with only one attestation
	if len(attestations) < 2 {
		return nil
	}

	// do some basic client side validation
	firstAttestation := attestations[0]

	attestationTimestamps := make([]int64, 0, len(attestations))
	attestationTimestamps = append(attestationTimestamps, firstAttestation.Timestamp)

	for _, att := range attestations[1:] {
		if options.DataShouldMatch && att.AttestationData != firstAttestation.AttestationData {
			return errors.New("attestation data mismatch")
		}

		// save the timestamps to check for time deviation of all attestations
		attestationTimestamps = append(attestationTimestamps, att.Timestamp)
	}

	if options.MaxTimeDeviation != nil {
		// warn the user that it's not recommended to have a deviation less than 10ms or more than 10s
		if *options.MaxTimeDeviation < 10 || *options.MaxTimeDeviation > 10*1000 {
			c.logger.Printf("Notarize: WARNING max time deviation for attestation of %dms is not recommended", *options.MaxTimeDeviation)
		}

		slices.Sort(attestationTimestamps)
		// test that all attestations were done within the allowed deviation.
		// the difference between the soonest and latest timestamps shouldn't be more than the configured deviation
		if attestationTimestamps[len(attestations)-1]-attestationTimestamps[0] > *options.MaxTimeDeviation {
			return errors.New("attestation timestamps deviate too much")
		}
	}

	return nil
}

type verifyRequest struct {
	Reports []*AttestationResponse `json:"reports"`
}
type verifyResponse struct {
	ValidReports []int  `json:"validReports"`
	ErrorMessage string `json:"errorMessage"`
}

func (c *Client) verifyReports(ctx context.Context, attestations []*AttestationResponse) ([]*AttestationResponse, error) {
	var wg sync.WaitGroup

	resChan := make(chan *verifyResponse, 1)
	errChan := make(chan error, 1)

	verifyMessage := &verifyRequest{
		Reports: attestations,
	}

	wg.Add(1)
	go executeRequest(
		"/verify",
		nil,
		&requestContext{Ctx: ctx, Method: http.MethodPost, Backend: c.verifier, Transport: c.transport},
		verifyMessage,
		&wg,
		resChan,
		errChan,
	)

	wg.Wait()

	close(resChan)
	close(errChan)

	if len(errChan) > 0 {
		err := <-errChan
		return nil, err
	}

	result := <-resChan

	if len(result.ValidReports) == 0 {
		return nil, errors.New(result.ErrorMessage)
	}

	var validAttestations []*AttestationResponse
	for i, attestation := range attestations {
		if slices.Contains(result.ValidReports, i) {
			validAttestations = append(validAttestations, attestation)
		}
	}

	if len(validAttestations) == 0 {
		return nil, errors.New("no valid attestations found")
	}

	return validAttestations, nil
}

// TestSelector response, which contains information for debugging selectors for extracting AttestationData for calling Notarize.
type TestSelectorResponse struct {
	// URL of the Notarization Backend the response came from.
	EnclaveUrl string `json:"enclaveUrl"`

	// Full response body received in the attestation target's response
	ResponseBody string `json:"responseBody"`

	// Status code of the attestation target's response
	ResponseStatusCode int `json:"responseStatusCode"`

	// Extracted data from ResponseBody using the provided selector
	ExtractedData string `json:"extractedData"`
}

// TestSelector method options.
type TestSelectorOptions struct {
	Context context.Context
}

// TestSelector is a function that can be used to test your requests without performing attestation and verification.
//
// Notarization Backend will try to request the attestation target and extract data with the provided selector.
// You can use the same request that you would use for Notarize to see if the Notarization Backend is able to get your data and correctly extract it.
// You will be able to see as a result the full ResponseBody, extracted data, response status code and errors if there are any.
//
// Options are optional. If nil, will use a 5-second timeout context.
func (c *Client) TestSelector(req *AttestationRequest, options *TestSelectorOptions) ([]*TestSelectorResponse, []error) {
	reqMessage := &attestationRequestMessage{
		AttestationRequest: *req,
		DebugRequest:       true,
	}

	// configure default options
	if options == nil {
		options = &TestSelectorOptions{}
	}

	if options.Context == nil {
		ctx, cancel := context.WithTimeout(context.Background(), DEFAULT_TIMEOUT)
		defer cancel()

		options.Context = ctx
	}

	numServices := len(c.notarizer)

	var wg sync.WaitGroup
	wg.Add(numServices)

	resChanMap := make(map[string]chan *TestSelectorResponse, numServices)
	errChan := make(chan error, numServices)

	for _, serviceConfig := range c.notarizer {
		resChanMap[serviceConfig.Address] = make(chan *TestSelectorResponse, 1)

		go executeRequest(
			"/notarize",
			nil,
			&requestContext{Ctx: options.Context, Method: http.MethodPost, Backend: serviceConfig, Transport: c.transport},
			reqMessage,
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
		}

		// all requests have failed
		if len(reqErrors) == numServices {
			return nil, reqErrors
		}
	}

	var result []*TestSelectorResponse
	for enclaveUrl, resChan := range resChanMap {
		resp := <-resChan
		resp.EnclaveUrl = enclaveUrl
		result = append(result, resp)
	}

	return result, nil
}
