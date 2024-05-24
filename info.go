package aleo_oracle_sdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
)

// GetEnclavesInfo options.
type EnclaveInfoOptions struct {
	// Optional enclave information request context. If not provided, uses a context with timeout of 5s.
	Context context.Context
}

// Contains information about an SGX enclave.
type SgxInfo struct {
	SecurityVersion uint      `json:"securityVersion"` // Security version of the enclave. For SGX enclaves, this is the ISVSVN value.
	Debug           bool      `json:"debug"`           // If true, the report is for a debug enclave.
	UniqueID        []byte    `json:"uniqueId"`        // The unique ID for the enclave. For SGX enclaves, this is the MRENCLAVE value.
	AleoUniqueID    [2]string `json:"aleoUniqueId"`    // Same as UniqueID but encoded for Aleo as 2 uint128
	SignerID        []byte    `json:"signerId"`        // The signer ID for the enclave. For SGX enclaves, this is the MRSIGNER value.
	AleoSignerID    [2]string `json:"aleoSignerId"`    // Same as SignerID but encoded for Aleo as 2 uint128
	ProductID       []byte    `json:"productId"`       // The Product ID for the enclave. For SGX enclaves, this is the ISVPRODID value.
	AleoProductID   string    `json:"aleoProductId"`   // Same as ProductID but encoded for Aleo as 1 uint128
	TCBStatus       uint      `json:"tcbStatus"`       // The status of the enclave's TCB level.
}

// Contains information about the TEE enclave that the Notarization Backend is running in
type EnclaveInfo struct {
	json.Unmarshaler

	// Url of the Notarization Backend the report came from.
	EnclaveUrl string

	// TEE that backend is running in
	ReportType string

	// This is a public key of the report signing key that was generated in the enclave.
	// The signing key is used to create Schnorr signatures,
	// and the public key is to be used to verify that signature inside of a program.
	// The public key is encoded to Aleo "address" type.
	SignerPubKey string

	// Information about the SGX. Exists only when ReportType is "sgx"
	SgxInfo *SgxInfo
}

// info response struct that is used internally to figure out the report type
// to use in EnclaveInfo
type enclaveInfoResponse struct {
	ReportType   string      `json:"reportType"`
	Info         interface{} `json:"info"`
	SignerPubKey string      `json:"signerPubKey"`
}

func (e *EnclaveInfo) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}

	internalStruct := new(enclaveInfoResponse)
	err := json.Unmarshal(b, internalStruct)
	if err != nil {
		return err
	}

	if internalStruct.ReportType == REPORT_TYPE_SGX {
		// this is really stupid but since go doesn't have info
		// about the underlying type we cannot do type assertions,
		// so as a workaround, we marshal the interface and unmarshal but into a type this time.
		// is there a better way?
		infoBytes, _ := json.Marshal(internalStruct.Info)
		e.SgxInfo = new(SgxInfo)
		err := json.Unmarshal(infoBytes, e.SgxInfo)
		if err != nil {
			return errors.New("sgx enclave provided unexpected self report")
		}

		e.EnclaveUrl = "" // should be filled by the client after unmarshalling
		e.ReportType = internalStruct.ReportType
		e.SignerPubKey = internalStruct.SignerPubKey
		return nil
	} else {
		return errors.New("enclave uses unknown report type")
	}
}

// GetEnclavesInfo requests information about the enclaves that the Notarization Backends are running in.
//
// Can be used to get such important information as security level or Enclave Unique ID, which can be used to verify that Notarization Backend is running the expected version of the code.
//
// Options are optional, will use 5-second timeout context if options are nil.
func (c *Client) GetEnclavesInfo(options *EnclaveInfoOptions) ([]*EnclaveInfo, []error) {
	if options == nil {
		ctx, cancel := context.WithTimeout(context.Background(), DEFAULT_TIMEOUT)
		defer cancel()

		options = &EnclaveInfoOptions{
			Context: ctx,
		}
	}

	numServices := len(c.notarizer)

	var wg sync.WaitGroup
	wg.Add(numServices)

	resChanMap := make(map[string]chan *EnclaveInfo, numServices)
	errChan := make(chan error, numServices)

	for _, serviceConfig := range c.notarizer {
		resChanMap[serviceConfig.Address] = make(chan *EnclaveInfo, 1)
		go executeRequest[interface{}, EnclaveInfo](
			"/info",
			&requestContext{Ctx: options.Context, Method: http.MethodGet, Backend: serviceConfig, Transport: c.transport},
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
		}

		return nil, reqErrors
	}

	var info []*EnclaveInfo
	for enclaveUrl, resChan := range resChanMap {
		enclaveInfo := <-resChan
		enclaveInfo.EnclaveUrl = enclaveUrl
		info = append(info, enclaveInfo)
	}

	return info, nil
}
