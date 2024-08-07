# Changelog

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
