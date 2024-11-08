# Changelog

## [2.1.0] - 07.11.2024

## Added

- Default Client config now includes AWS Nitro notarizer

## Changed

- Client will no longer report an error if one of multiple attestations has failed verification, the client will return all verified attestations as long as there is at least one

## Fixed

- Attestation time deviation check

## [2.0.1] - 26.09.2024

### Fixed

- Change Go module name to github.com/zkportal/aleo-oracle-sdk-go/v2

## [2.0.0] - 19.09.2024

### Breaking

- Changes in `SgxInfo` type

### Added

- `OracleData.ReportExtras` optional field with some extra encoding information about the attestation report

## [1.2.0] - 28.08.2024

### Added

- New client method `GetAttestedRandom` for getting attested random numbers

## [1.1.4] - 07.08.2024

### Fixed

- Don't use `http.DefaultTransport` at all

## [1.1.3] - 07.08.2024

### Fixed

- Client's TLS config bleeding into `http.DefaultClient`

## [1.1.2] - 03.06.2024

### Fixed

- Client hanging when handling multiple notarization errors under certain conditions

## [1.1.1] - 27.05.2024

### Fixed

- Verification returning an error when it's resolved after using resolved notarizer

## [1.1.0] - 24.05.2024

### Added

- Support for higher availability of the default notarization and verification backends

### Changed

- **BREAKING** - `CustomBackendConfig`'s `URL` is now split into multiple fields

## [1.0.0] - 13.05.2024

First public release of Aleo Oracle SDK for Go.
