use std::fmt;

use crate::algorithm::Algorithm;
use crate::errors::Error;
use crate::integrity::Integrity;

use digest::Digest as DigestTrait;

/// Successful integrity verification metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Verification {
    /// The strongest algorithm group used for verification.
    pub algorithm: Algorithm,
    /// The matching digest index inside the expected [`Integrity`].
    pub matched_index: usize,
}

/**
Streaming verifier for an [`Integrity`].

# Examples

```
# use ssri2::{Algorithm, Integrity};
let data = b"hello world";
let sri = Integrity::digest(data, Algorithm::Sha256);
let verification = sri.checker().chain(data).finish().unwrap();
assert_eq!(verification.algorithm, Algorithm::Sha256);
```
*/
#[derive(Debug)]
pub struct Checker<'a> {
    expected: &'a Integrity,
    hasher: ActiveHasher,
}

impl<'a> Checker<'a> {
    pub(crate) fn new(expected: &'a Integrity) -> Self {
        Self {
            expected,
            hasher: ActiveHasher::new(expected.strongest_algorithm()),
        }
    }

    /// Add bytes to the running verifier.
    pub fn update<B: AsRef<[u8]>>(&mut self, data: B) {
        self.hasher.update(data.as_ref());
    }

    /// Add bytes to the running verifier and return `self` for chaining.
    pub fn chain<B: AsRef<[u8]>>(mut self, data: B) -> Self {
        self.update(data);
        self
    }

    /// Finish verification and return the matching algorithm and digest index.
    pub fn finish(self) -> Result<Verification, Error> {
        let (algorithm, digest, len) = self.hasher.finalize();
        let digest = &digest[..len];

        self.expected
            .selected()
            .find(|expected| expected.bytes() == digest)
            .map(|expected| Verification {
                algorithm,
                matched_index: expected.index(),
            })
            .ok_or(Error::IntegrityMismatch { algorithm })
    }
}

enum ActiveHasher {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Xxh3(Box<xxhash_rust::xxh3::Xxh3>),
}

impl fmt::Debug for ActiveHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1(_) => f.write_str("Sha1"),
            Self::Sha256(_) => f.write_str("Sha256"),
            Self::Sha384(_) => f.write_str("Sha384"),
            Self::Sha512(_) => f.write_str("Sha512"),
            Self::Xxh3(_) => f.write_str("Xxh3"),
        }
    }
}

impl ActiveHasher {
    fn new(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Sha1 => Self::Sha1(sha1::Sha1::new()),
            Algorithm::Sha256 => Self::Sha256(sha2::Sha256::new()),
            Algorithm::Sha384 => Self::Sha384(sha2::Sha384::new()),
            Algorithm::Sha512 => Self::Sha512(sha2::Sha512::new()),
            Algorithm::Xxh3 => Self::Xxh3(Box::new(xxhash_rust::xxh3::Xxh3::new())),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(hasher) => DigestTrait::update(hasher, data),
            Self::Sha256(hasher) => DigestTrait::update(hasher, data),
            Self::Sha384(hasher) => DigestTrait::update(hasher, data),
            Self::Sha512(hasher) => DigestTrait::update(hasher, data),
            Self::Xxh3(hasher) => hasher.update(data),
        }
    }

    fn finalize(self) -> (Algorithm, [u8; 64], usize) {
        match self {
            Self::Sha1(hasher) => finalize_digest(Algorithm::Sha1, hasher.finalize().as_ref()),
            Self::Sha256(hasher) => finalize_digest(Algorithm::Sha256, hasher.finalize().as_ref()),
            Self::Sha384(hasher) => finalize_digest(Algorithm::Sha384, hasher.finalize().as_ref()),
            Self::Sha512(hasher) => finalize_digest(Algorithm::Sha512, hasher.finalize().as_ref()),
            Self::Xxh3(hasher) => {
                finalize_digest(Algorithm::Xxh3, &hasher.digest128().to_be_bytes())
            }
        }
    }
}

fn finalize_digest(algorithm: Algorithm, digest: &[u8]) -> (Algorithm, [u8; 64], usize) {
    let mut bytes = [0; 64];
    bytes[..digest.len()].copy_from_slice(digest);
    (algorithm, bytes, digest.len())
}

#[cfg(test)]
mod tests {
    use super::Algorithm;
    use super::Error;
    use crate::Integrity;

    #[test]
    fn basic_test() {
        let sri = Integrity::digest(b"hello world", Algorithm::Sha256);
        let result = sri.checker().chain(b"hello world").finish();
        assert_eq!(result.unwrap().algorithm, Algorithm::Sha256)
    }

    #[test]
    fn multi_hash_checks_strongest_group() {
        let sri = Integrity::digest(b"goodbye world", Algorithm::Sha256)
            .concat(&Integrity::digest(b"hello world", Algorithm::Sha256));
        let result = sri.checker().chain(b"hello world").finish();
        assert_eq!(result.unwrap().matched_index, 1)
    }

    #[test]
    fn weaker_algorithm_match_does_not_verify() {
        let expected = Integrity::digest(b"strong data", Algorithm::Sha512)
            .concat(&Integrity::digest(b"hello world", Algorithm::Sha256));

        assert_eq!(
            expected.verify(b"hello world"),
            Err(Error::IntegrityMismatch {
                algorithm: Algorithm::Sha512,
            })
        );
    }
}
