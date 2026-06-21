use std::fmt;

use crate::algorithm::Algorithm;
use crate::checker::{Checker, Verification};
use crate::errors::Error;
use crate::hash::Hash;
use crate::opts::IntegrityBuilder;

use digest::Digest as DigestTrait;

#[cfg(feature = "serde")]
use serde::de::{self, Deserialize, Deserializer, Visitor};
#[cfg(feature = "serde")]
use serde::ser::{Serialize, Serializer};

/**
Representation of a full [Subresource Integrity string](https://w3c.github.io/webappsec/specs/subresourceintegrity/).

# Example

```
# use ssri2::Integrity;
let source = "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";

let parsed: Integrity = source.parse().unwrap();
assert_eq!(parsed.to_string(), source);
```
*/
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Integrity {
    repr: Repr,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Repr {
    One(Hash),
    Many(Box<[Hash]>),
}

/// Borrowed view of one digest inside an [`Integrity`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DigestRef<'a> {
    index: usize,
    hash: &'a Hash,
}

impl DigestRef<'_> {
    /// Return this digest's index in its parent [`Integrity`].
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Return the digest algorithm.
    pub const fn algorithm(&self) -> Algorithm {
        self.hash.algorithm()
    }

    /// Return raw digest bytes.
    pub fn bytes(&self) -> &[u8] {
        self.hash.digest_bytes()
    }

    /// Return the digest encoded as canonical padded standard base64.
    pub fn to_base64(&self) -> String {
        self.hash.digest_base64()
    }

    /// Return the digest encoded as lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes())
    }
}

impl fmt::Display for DigestRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.hash.fmt(f)
    }
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, digest) in self.iter().enumerate() {
            if i != 0 {
                f.write_str(" ")?;
            }
            digest.fmt(f)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Integrity {
    type Err = Error;

    /// Parses a string into an Integrity instance.
    fn from_str(s: &str) -> Result<Integrity, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Integrity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Integrity {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IntegrityVisitor;

        impl<'de> Visitor<'de> for IntegrityVisitor {
            type Value = Integrity;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an Integrity object as a string")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                v.parse::<Integrity>().map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(IntegrityVisitor)
    }
}

impl Integrity {
    pub(crate) fn from_hash(hash: Hash) -> Self {
        Self {
            repr: Repr::One(hash),
        }
    }

    pub(crate) fn from_hashes(hashes: Vec<Hash>) -> Result<Self, Error> {
        let mut hashes = match hashes.len() {
            0 => return Err(Error::NoAlgorithms),
            1 => {
                return Ok(Self {
                    repr: Repr::One(hashes.into_iter().next().expect("length checked")),
                });
            }
            _ => hashes,
        };

        let mut hashes = hashes.drain(..).fold(Vec::new(), |mut unique, hash| {
            if !unique.contains(&hash) {
                unique.push(hash);
            }
            unique
        });
        hashes.sort();

        let repr = if hashes.len() == 1 {
            Repr::One(hashes.pop().expect("length checked"))
        } else {
            Repr::Many(hashes.into_boxed_slice())
        };

        Ok(Self { repr })
    }

    pub(crate) fn from_ordered_hashes(mut hashes: Vec<Hash>) -> Result<Self, Error> {
        let repr = match hashes.len() {
            0 => return Err(Error::NoAlgorithms),
            1 => Repr::One(hashes.pop().expect("length checked")),
            _ => Repr::Many(hashes.into_boxed_slice()),
        };

        Ok(Self { repr })
    }

    /// Parse a strict SRI integrity string.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let mut tokens = input.split_whitespace();
        let Some(first) = tokens.next() else {
            return Err(Error::EmptyIntegrity);
        };

        let first = first.parse()?;
        let Some(second) = tokens.next() else {
            return Ok(Self {
                repr: Repr::One(first),
            });
        };

        let mut hashes = vec![first, second.parse()?];
        for token in tokens {
            hashes.push(token.parse()?);
        }
        Self::from_hashes(hashes)
    }

    /// Generate a single-digest integrity value.
    pub fn digest<B: AsRef<[u8]>>(data: B, algorithm: Algorithm) -> Self {
        let data = data.as_ref();
        let hash = match algorithm {
            Algorithm::Sha1 => Hash::from_algorithm_digest(algorithm, sha1::Sha1::digest(data)),
            Algorithm::Sha256 => Hash::from_algorithm_digest(algorithm, sha2::Sha256::digest(data)),
            Algorithm::Sha384 => Hash::from_algorithm_digest(algorithm, sha2::Sha384::digest(data)),
            Algorithm::Sha512 => Hash::from_algorithm_digest(algorithm, sha2::Sha512::digest(data)),
            Algorithm::Xxh3 => {
                let mut hasher = xxhash_rust::xxh3::Xxh3::new();
                hasher.update(data);
                Hash::from_algorithm_digest(algorithm, hasher.digest128().to_be_bytes())
            }
        }
        .expect("hash output length matches algorithm");

        Self::from_hash(hash)
    }

    /// Generate an integrity value with multiple algorithms.
    pub fn digest_many<B, I>(data: B, algorithms: I) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
        I: IntoIterator<Item = Algorithm>,
    {
        let data = data.as_ref();
        let mut builder = IntegrityBuilder::new();
        for algorithm in algorithms {
            builder = builder.algorithm(algorithm);
        }
        builder.update(data);
        builder.finish()
    }

    /// Create an integrity value from one raw digest.
    pub fn from_digest<D>(algorithm: Algorithm, digest: D) -> Result<Self, Error>
    where
        D: AsRef<[u8]>,
    {
        Self::from_hashes(vec![Hash::from_algorithm_digest(algorithm, digest)?])
    }

    /// Create an integrity value from one standard base64 digest.
    pub fn from_digest_base64<D>(algorithm: Algorithm, digest: D) -> Result<Self, Error>
    where
        D: AsRef<[u8]>,
    {
        Self::from_hashes(vec![Hash::from_algorithm_digest_base64(algorithm, digest)?])
    }

    /// Create an integrity value from one hex digest.
    pub fn from_digest_hex<D>(algorithm: Algorithm, digest: D) -> Result<Self, Error>
    where
        D: AsRef<[u8]>,
    {
        let digest = hex::decode(digest).map_err(|e| Error::HexDecodeError(e.to_string()))?;
        Self::from_digest(algorithm, digest)
    }

    /// Return all digests in strongest-algorithm-first order.
    pub fn iter(&self) -> impl Iterator<Item = DigestRef<'_>> + '_ {
        self.hashes()
            .iter()
            .enumerate()
            .map(|(index, hash)| DigestRef { index, hash })
    }

    /// Return the strongest algorithm group selected for verification.
    pub fn selected(&self) -> impl Iterator<Item = DigestRef<'_>> + '_ {
        self.selected_hashes()
            .iter()
            .enumerate()
            .map(|(index, hash)| DigestRef { index, hash })
    }

    /// Return the first digest.
    pub fn first(&self) -> DigestRef<'_> {
        self.iter().next().expect("integrity is never empty")
    }

    /// Return the number of digests.
    pub fn len(&self) -> usize {
        self.hashes().len()
    }

    /// Return whether this integrity value is empty.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Return the strongest available algorithm in this integrity value.
    pub fn strongest_algorithm(&self) -> Algorithm {
        self.hashes()[0].algorithm()
    }

    /// Join together two `Integrity` instances.
    pub fn concat(&self, other: &Integrity) -> Self {
        if self == other {
            return self.clone();
        }

        if let (Repr::One(left), Repr::One(right)) = (&self.repr, &other.repr) {
            let mut hashes = vec![left.clone(), right.clone()];
            hashes.sort();
            return Self::from_ordered_hashes(hashes).expect("two hashes are non-empty");
        }

        let hashes = self
            .hashes()
            .iter()
            .chain(other.hashes())
            .cloned()
            .collect();
        Self::from_hashes(hashes).expect("source integrities are never empty")
    }

    /// Verify bytes against this integrity value.
    pub fn verify<B: AsRef<[u8]>>(&self, data: B) -> Result<Verification, Error> {
        self.checker().chain(data).finish()
    }

    /// Create a streaming verifier for this integrity value.
    pub fn checker(&self) -> Checker<'_> {
        Checker::new(self)
    }

    /// Compare two integrity values using `other` to choose the strongest
    /// algorithm group.
    pub fn matches(&self, other: &Self) -> Option<Algorithm> {
        let algorithm = other.strongest_algorithm();
        let selected = other.selected_hashes();
        let matches = self
            .hashes()
            .iter()
            .filter(|digest| digest.algorithm() == algorithm)
            .any(|digest| selected.iter().any(|other_digest| digest == other_digest));

        matches.then_some(algorithm)
    }

    fn hashes(&self) -> &[Hash] {
        match &self.repr {
            Repr::One(hash) => std::slice::from_ref(hash),
            Repr::Many(hashes) => hashes,
        }
    }

    fn selected_hashes(&self) -> &[Hash] {
        let hashes = self.hashes();
        let algorithm = hashes[0].algorithm();
        let end = hashes
            .iter()
            .take_while(|hash| hash.algorithm() == algorithm)
            .count();
        &hashes[..end]
    }
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, Integrity};
    use crate::Error;

    #[test]
    fn parse() {
        let sri: Integrity = "sha1-Kq5sNclPz7QV2+lfQIuc6R7oRu0=".parse().unwrap();
        let digest = sri.first();
        assert_eq!(digest.algorithm(), Algorithm::Sha1);
        assert_eq!(digest.to_base64(), "Kq5sNclPz7QV2+lfQIuc6R7oRu0=");
    }

    #[test]
    fn parse_empty_integrity_fails() {
        assert_eq!("  \n\t ".parse::<Integrity>(), Err(Error::EmptyIntegrity));
    }

    #[test]
    fn parse_rejects_issue_5_short_sha256_digest() {
        assert!(matches!(
            "sha256-pc6cFV7Qk5dhRkbJcX/HzZSxAj17drYY1Ank".parse::<Integrity>(),
            Err(Error::InvalidDigestLength {
                algorithm: Algorithm::Sha256,
                expected: 32,
                actual: 27,
            })
        ));
    }

    #[test]
    fn parse_rejects_invalid_base64_digest() {
        assert!(matches!(
            "sha256-not-valid!!!".parse::<Integrity>(),
            Err(Error::InvalidBase64Digest(_))
        ));
    }

    #[test]
    fn parse_rejects_extra_dash_segment() {
        assert!(matches!(
            "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=-extra".parse::<Integrity>(),
            Err(Error::InvalidBase64Digest(_))
        ));
    }

    #[test]
    fn from_digest_hex_rejects_wrong_digest_length() {
        assert!(matches!(
            Integrity::from_digest_hex(Algorithm::Sha256, "deadbeef"),
            Err(Error::InvalidDigestLength {
                algorithm: Algorithm::Sha256,
                expected: 32,
                actual: 4,
            })
        ));
    }

    #[test]
    fn from_digest_hex() {
        let expected_integrity = Integrity::digest(b"hello world", Algorithm::Sha256);
        let hex = String::from("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        assert_eq!(
            Integrity::from_digest_hex(Algorithm::Sha256, hex).unwrap(),
            expected_integrity
        );
    }

    #[test]
    fn digest_ref_to_hex() {
        let sri = Integrity::digest(b"hello world", Algorithm::Sha256);
        let digest = sri.first();
        assert_eq!(digest.algorithm(), Algorithm::Sha256);
        assert_eq!(
            digest.to_hex(),
            String::from("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        )
    }

    #[test]
    fn matches() {
        let sri1 =
            Integrity::digest_many(b"hello world", [Algorithm::Sha512, Algorithm::Sha256]).unwrap();
        let sri2 = Integrity::digest(b"hello world", Algorithm::Sha256);
        let sri3 = Integrity::digest(b"goodbye world", Algorithm::Sha256);
        assert_eq!(sri1.matches(&sri2), Some(Algorithm::Sha256));
        assert_eq!(sri1.matches(&sri3), None);
        assert_eq!(sri2.matches(&sri1), None)
    }

    #[test]
    fn concat_deduplicates() {
        let sri = Integrity::digest(b"hello world", Algorithm::Sha256);
        let concat = sri.concat(&sri);
        assert_eq!(concat.len(), 1);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn de_json() {
        use serde_derive::Deserialize;

        #[derive(Debug, PartialEq, Deserialize)]
        struct Thing {
            integrity: Integrity,
        }

        let json = r#"{ "integrity": "sha1-Kq5sNclPz7QV2+lfQIuc6R7oRu0=" }"#;
        let de: Thing = serde_json::from_str(json).unwrap();

        assert_eq!(
            de,
            Thing {
                integrity: "sha1-Kq5sNclPz7QV2+lfQIuc6R7oRu0=".parse().unwrap()
            }
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn de_json_rejects_invalid_digest_length() {
        use serde_derive::Deserialize;

        #[derive(Debug, PartialEq, Deserialize)]
        struct Thing {
            integrity: Integrity,
        }

        let json = r#"{ "integrity": "sha256-pc6cFV7Qk5dhRkbJcX/HzZSxAj17drYY1Ank" }"#;

        assert!(serde_json::from_str::<Thing>(json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn ser_json() {
        use serde_derive::Serialize;

        #[derive(Debug, PartialEq, Serialize)]
        struct Thing {
            integrity: Integrity,
        }

        let thing = Thing {
            integrity: "sha1-Kq5sNclPz7QV2+lfQIuc6R7oRu0=".parse().unwrap(),
        };
        let ser = serde_json::to_string(&thing).unwrap();
        let json = r#"{"integrity":"sha1-Kq5sNclPz7QV2+lfQIuc6R7oRu0="}"#;

        assert_eq!(ser, json);
    }
}
