use std::cmp::Ordering;
use std::fmt;

use base64_simd::{AsOut, STANDARD as BASE64_STANDARD};

use crate::algorithm::Algorithm;
use crate::errors::Error;

pub(crate) const MAX_BASE64_DIGEST_LEN: usize = 88;

/**
Represents a single algorithm/digest pair.

This is mostly internal, although users might interact with it directly on
occasion.
*/
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Hash {
    digest: DigestBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum DigestBytes {
    Sha512([u8; 64]),
    Sha384([u8; 48]),
    Sha256([u8; 32]),
    Sha1([u8; 20]),
    Xxh3([u8; 16]),
}

impl DigestBytes {
    const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Sha512(_) => Algorithm::Sha512,
            Self::Sha384(_) => Algorithm::Sha384,
            Self::Sha256(_) => Algorithm::Sha256,
            Self::Sha1(_) => Algorithm::Sha1,
            Self::Xxh3(_) => Algorithm::Xxh3,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Sha512(digest) => digest,
            Self::Sha384(digest) => digest,
            Self::Sha256(digest) => digest,
            Self::Sha1(digest) => digest,
            Self::Xxh3(digest) => digest,
        }
    }
}

impl Hash {
    /// Creates a hash from an algorithm and raw digest bytes.
    pub(crate) fn from_algorithm_digest<D>(algorithm: Algorithm, digest: D) -> Result<Self, Error>
    where
        D: AsRef<[u8]>,
    {
        let digest = digest.as_ref();
        let expected = algorithm.digest_len();
        let actual = digest.len();

        if actual != expected {
            return Err(Error::InvalidDigestLength {
                algorithm,
                expected,
                actual,
            });
        }

        let digest = match algorithm {
            Algorithm::Sha512 => DigestBytes::Sha512(digest.try_into().expect("length checked")),
            Algorithm::Sha384 => DigestBytes::Sha384(digest.try_into().expect("length checked")),
            Algorithm::Sha256 => DigestBytes::Sha256(digest.try_into().expect("length checked")),
            Algorithm::Sha1 => DigestBytes::Sha1(digest.try_into().expect("length checked")),
            Algorithm::Xxh3 => DigestBytes::Xxh3(digest.try_into().expect("length checked")),
        };

        Ok(Self { digest })
    }

    /// Creates a hash from an algorithm and a standard base64-encoded digest.
    pub(crate) fn from_algorithm_digest_base64<D>(
        algorithm: Algorithm,
        digest: D,
    ) -> Result<Self, Error>
    where
        D: AsRef<[u8]>,
    {
        let digest = BASE64_STANDARD
            .decode_to_vec(digest)
            .map_err(|e| Error::InvalidBase64Digest(e.to_string()))?;
        Self::from_algorithm_digest(algorithm, digest)
    }

    /// Returns the algorithm for this hash.
    pub(crate) const fn algorithm(&self) -> Algorithm {
        self.digest.algorithm()
    }

    /// Returns the raw digest bytes.
    pub(crate) fn digest_bytes(&self) -> &[u8] {
        self.digest.as_bytes()
    }

    /// Returns the digest encoded as canonical padded standard base64.
    pub(crate) fn digest_base64(&self) -> String {
        BASE64_STANDARD.encode_to_string(self.digest_bytes())
    }

    pub(crate) fn digest_base64_into<'a>(
        &self,
        dst: &'a mut [u8; MAX_BASE64_DIGEST_LEN],
    ) -> &'a str {
        BASE64_STANDARD.encode_as_str(self.digest_bytes(), dst.as_mut_slice().as_out())
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Hash) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Hash) -> Ordering {
        self.algorithm().cmp(&other.algorithm())
    }
}
impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut digest = [0; MAX_BASE64_DIGEST_LEN];
        let digest = self.digest_base64_into(&mut digest);
        write!(f, "{}-{digest}", self.algorithm())
    }
}

impl std::str::FromStr for Hash {
    type Err = Error;

    /// Tries to parse a [&str] into a [struct@Hash].
    fn from_str(s: &str) -> Result<Hash, Self::Err> {
        let s = s.trim();
        let (algorithm, digest) = s
            .split_once('-')
            .ok_or_else(|| Error::MalformedIntegrity(s.into()))?;

        if digest.is_empty() {
            return Err(Error::MalformedIntegrity(s.into()));
        }

        Hash::from_algorithm_digest_base64(algorithm.parse()?, digest)
    }
}

#[cfg(test)]
mod tests {
    use super::Hash;
    use crate::Algorithm;
    use crate::Error;

    const SHA1_BASE64: &str = "Kq5sNclPz7QV2+lfQIuc6R7oRu0=";
    const SHA256_BASE64: &str = "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";
    const SHA384_BASE64: &str = "v9dsDrvQBv7lg0EFR8GIewKSvnbVgtlsJC0qeScj4f3QZCMg0Yd6QwG7Zwoqmsf2";
    const SHA512_BASE64: &str =
        "MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1m9NDxsfkgb3TNTNwFdaTCQwZt9dyj2OXff0mK2r9kMDRHvg==";
    const XXH3_BASE64: &str = "MdaImY0CFZUTMhcVNi9apA==";

    #[test]
    fn hash_stringify() {
        let hash = Hash::from_algorithm_digest_base64(Algorithm::Sha256, SHA256_BASE64).unwrap();
        assert_eq!(format!("{}", hash), format!("sha256-{SHA256_BASE64}"))
    }

    #[test]
    fn parsing() {
        let parsed = format!(" sha256-{SHA256_BASE64} \n")
            .parse::<Hash>()
            .unwrap();
        assert_eq!(parsed.algorithm(), Algorithm::Sha256);
        assert_eq!(parsed.digest_base64(), SHA256_BASE64);
    }

    #[test]
    fn constructors_expose_digest_accessors() {
        let hash = Hash::from_algorithm_digest(Algorithm::Sha1, [0; 20]).unwrap();
        assert_eq!(hash.algorithm(), Algorithm::Sha1);
        assert_eq!(hash.digest_bytes(), &[0; 20]);
        assert_eq!(hash.digest_base64(), "AAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    }

    #[test]
    fn parses_all_supported_algorithm_lengths() {
        for (algorithm, digest) in [
            (Algorithm::Sha1, SHA1_BASE64),
            (Algorithm::Sha256, SHA256_BASE64),
            (Algorithm::Sha384, SHA384_BASE64),
            (Algorithm::Sha512, SHA512_BASE64),
            (Algorithm::Xxh3, XXH3_BASE64),
        ] {
            let hash = Hash::from_algorithm_digest_base64(algorithm, digest).unwrap();
            assert_eq!(hash.algorithm(), algorithm);
            assert_eq!(hash.digest_bytes().len(), algorithm.digest_len());
        }
    }

    #[test]
    fn bad_algorithm() {
        assert!(matches!(
            "sha7-deadbeef==".parse::<Hash>(),
            Err(Error::UnknownAlgorithm(_))
        ));
    }

    #[test]
    fn bad_length_short() {
        assert!(matches!(
            Hash::from_algorithm_digest(Algorithm::Sha256, [0; 31]),
            Err(Error::InvalidDigestLength {
                algorithm: Algorithm::Sha256,
                expected: 32,
                actual: 31,
            })
        ));
    }

    #[test]
    fn bad_length_long() {
        assert!(matches!(
            Hash::from_algorithm_digest(Algorithm::Sha256, [0; 33]),
            Err(Error::InvalidDigestLength {
                algorithm: Algorithm::Sha256,
                expected: 32,
                actual: 33,
            })
        ));
    }

    #[test]
    fn invalid_base64() {
        assert!(matches!(
            "sha256-not-valid!!!".parse::<Hash>(),
            Err(Error::InvalidBase64Digest(_))
        ));
    }

    #[test]
    fn extra_dash_is_invalid_base64() {
        assert!(matches!(
            format!("sha256-{SHA256_BASE64}-extra").parse::<Hash>(),
            Err(Error::InvalidBase64Digest(_))
        ));
    }

    #[test]
    fn empty_digest() {
        assert!(matches!(
            "sha256-".parse::<Hash>(),
            Err(Error::MalformedIntegrity(_))
        ));
    }

    #[test]
    fn issue_5_short_sha256_digest_is_rejected() {
        assert!(matches!(
            "sha256-pc6cFV7Qk5dhRkbJcX/HzZSxAj17drYY1Ank".parse::<Hash>(),
            Err(Error::InvalidDigestLength {
                algorithm: Algorithm::Sha256,
                expected: 32,
                actual: 27,
            })
        ));
    }

    #[test]
    fn ordering() {
        let mut arr = [
            Hash::from_algorithm_digest(Algorithm::Sha1, [0; 20]).unwrap(),
            Hash::from_algorithm_digest(Algorithm::Sha256, [0; 32]).unwrap(),
            Hash::from_algorithm_digest(Algorithm::Sha384, [0; 48]).unwrap(),
            Hash::from_algorithm_digest(Algorithm::Sha512, [0; 64]).unwrap(),
            Hash::from_algorithm_digest(Algorithm::Xxh3, [0; 16]).unwrap(),
        ];
        arr.sort_unstable();
        assert_eq!(
            arr.iter().map(Hash::algorithm).collect::<Vec<_>>(),
            [
                Algorithm::Sha512,
                Algorithm::Sha384,
                Algorithm::Sha256,
                Algorithm::Sha1,
                Algorithm::Xxh3,
            ]
        )
    }
}
