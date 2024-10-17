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

type SgxAleoInfo struct {
	UniqueID  string `json:"uniqueId"`  // Same as UniqueID but encoded for Aleo as 2 uint128
	SignerID  string `json:"signerId"`  // Same as SignerID but encoded for Aleo as 2 uint128
	ProductID string `json:"productId"` // Same as ProductID but encoded for Aleo as 1 uint128
}

// Contains information about an SGX enclave.
type SgxInfo struct {
	SecurityVersion uint        `json:"securityVersion"` // Security version of the enclave. For SGX enclaves, this is the ISVSVN value.
	Debug           bool        `json:"debug"`           // If true, the report is for a debug enclave.
	UniqueID        []byte      `json:"uniqueId"`        // The unique ID for the enclave. For SGX enclaves, this is the MRENCLAVE value.
	SignerID        []byte      `json:"signerId"`        // The signer ID for the enclave. For SGX enclaves, this is the MRSIGNER value.
	ProductID       []byte      `json:"productId"`       // The Product ID for the enclave. For SGX enclaves, this is the ISVPRODID value.
	Aleo            SgxAleoInfo `json:"aleo"`            // Some of the SGX report values encoded for Aleo.
	TCBStatus       uint        `json:"tcbStatus"`       // The status of the enclave's TCB level.
}

type NitroDocument struct {
	// Issuing Nitro hypervisor module ID.
	ModuleID string `json:"moduleID"`

	// UTC time when document was created, in milliseconds since UNIX epoch.
	Timestamp int64 `json:"timestamp"`

	// The digest function used for calculating the register values.
	Digest string `json:"digest"`

	// Map of all locked PCRs at the moment the attestation document was generated.
	// The PCR keys are 0-15. All PCR values are 48 bytes long. Base64.
	PCRs map[string]string `json:"pcrs"`

	// The public key certificate for the public key that was used to sign the attestation document. Base64.
	Certificate string `json:"certificate"`

	// Issuing CA bundle for infrastructure certificate. Base64.
	CABundle []string `json:"cabundle"`

	// Additional signed user data. Always zero in a self report. Base64.
	UserData string `json:"userData"`

	// An optional cryptographic nonce provided by the attestation consumer as a proof of authenticity. Base64.
	Nonce string `json:"nonce"`
}

type NitroAleoInfo struct {
	// PCRs 0-2 encoded for Aleo as one struct of 9 `u128` fields, 3 chunks per PCR value.
	//
	// Example:
	//
	// "{ pcr_0_chunk_1: 286008366008963534325731694016530740873u128, pcr_0_chunk_2: 271752792258401609961977483182250439126u128, pcr_0_chunk_3: 298282571074904242111697892033804008655u128, pcr_1_chunk_1: 160074764010604965432569395010350367491u128, pcr_1_chunk_2: 139766717364114533801335576914874403398u128, pcr_1_chunk_3: 227000420934281803670652481542768973666u128, pcr_2_chunk_1: 280126174936401140955388060905840763153u128, pcr_2_chunk_2: 178895560230711037821910043922200523024u128, pcr_2_chunk_3: 219470830009272358382732583518915039407u128 }"
	PCRs string `json:"pcrs"`

	// Self report user data (always zero) encoded for Aleo as a `u128`.
	//
	// Example:
	//
	// "0u128"
	UserData string `json:"userData"`
}

type NitroInfo struct {
	// Nitro enclave attestation document.
	Document NitroDocument `json:"document"`

	// Protected section from the COSE Sign1 payload of the Nitro enclave attestation result. Base64.
	ProtectedCose string `json:"protectedCose"`

	// Signature section from the COSE Sign1 payload of the Nitro enclave attestation document. Base64.
	Signature string `json:"signature"`

	// Some of the Nitro document values encoded for Aleo.
	Aleo NitroAleoInfo `json:"aleo"`
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

	// Information about the SGX enclave. Exists only when ReportType is "sgx"
	SgxInfo *SgxInfo

	// Information about the Nitro enclave. Exists only when ReportType is "nitro"
	NitroInfo *NitroInfo
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
	} else if internalStruct.ReportType == REPORT_TYPE_NITRO {
		infoBytes, _ := json.Marshal(internalStruct.Info)
		e.NitroInfo = new(NitroInfo)
		err := json.Unmarshal(infoBytes, e.NitroInfo)
		if err != nil {
			return errors.New("nitro enclave provided unexpected self report")
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
			nil,
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

		// all request have failed
		if len(reqErrors) == numServices {
			return nil, reqErrors
		}
	}

	var info []*EnclaveInfo
	for enclaveUrl, resChan := range resChanMap {
		enclaveInfo := <-resChan
		enclaveInfo.EnclaveUrl = enclaveUrl
		info = append(info, enclaveInfo)
	}

	return info, nil
}
