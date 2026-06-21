use thiserror::Error;

use crate::Algorithm;

/// Integrity-related error values.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Error parsing an SRI string into an Integrity object.
    #[error("Failed to parse subresource integrity string: {0}")]
    ParseIntegrityError(String),
    /// Error parsing an unknown integrity algorithm.
    #[error("Unknown integrity algorithm: {0}")]
    UnknownAlgorithm(String),
    /// Error parsing a malformed integrity string.
    #[error("Malformed subresource integrity string: {0}")]
    MalformedIntegrity(String),
    /// Error parsing an empty integrity string.
    #[error("Subresource integrity string is empty")]
    EmptyIntegrity,
    /// Error decoding a base64 digest.
    #[error("Invalid base64 digest: {0}")]
    InvalidBase64Digest(String),
    /// Error caused by a digest length that does not match its algorithm.
    #[error("Invalid {algorithm} digest length: expected {expected} bytes, got {actual} bytes")]
    InvalidDigestLength {
        algorithm: Algorithm,
        expected: usize,
        actual: usize,
    },
    /// Error caused by finalizing a builder without configured algorithms.
    #[error("Cannot build an integrity value without configured algorithms")]
    NoAlgorithms,
    /// Error verifying bytes against an Integrity value.
    #[error("Integrity check failed for algorithm: {algorithm}")]
    IntegrityMismatch { algorithm: Algorithm },
    /// Error Decoding Hex Data
    #[error("Failed decode hexadecimal data, reason: {0}")]
    HexDecodeError(String),
}
