use std::fmt;

use crate::errors::Error;

/**
Valid algorithms for integrity strings.

`Sha1` and `Xxh3` are special cases in this library--they're not allowed by the
current SRI spec, but they're useful enough that having first-class support
makes sense. They should also be completely harmless to have in your strings
if you do use it in a browser context--they just won't be used.
*/
#[non_exhaustive]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithm {
    Sha512,
    Sha384,
    Sha256,
    Sha1,
    /// xxh3 is a non-cryptographic hash function that is very fast and can be
    /// used to speed up integrity calculations, at the cost of
    /// cryptographically-secure guarantees.
    ///
    /// `ssri2` uses 128-bit xxh3 hashes, which have been shown to have no
    /// conflicts even on billions of hashes.
    Xxh3,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Algorithm {
    /// Returns the canonical lowercase SRI algorithm name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha512 => "sha512",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha1 => "sha1",
            Algorithm::Xxh3 => "xxh3",
        }
    }

    /// Returns the digest length, in bytes, for this algorithm.
    pub const fn digest_len(self) -> usize {
        match self {
            Algorithm::Sha512 => 64,
            Algorithm::Sha384 => 48,
            Algorithm::Sha256 => 32,
            Algorithm::Sha1 => 20,
            Algorithm::Xxh3 => 16,
        }
    }
}

impl std::str::FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Algorithm, Self::Err> {
        match s {
            "sha1" => Ok(Algorithm::Sha1),
            "sha256" => Ok(Algorithm::Sha256),
            "sha384" => Ok(Algorithm::Sha384),
            "sha512" => Ok(Algorithm::Sha512),
            "xxh3" => Ok(Algorithm::Xxh3),
            _ => Err(Error::UnknownAlgorithm(s.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Algorithm::*;

    #[test]
    fn algorithm_formatting() {
        assert_eq!(format!("{}", Sha1), "sha1");
        assert_eq!(format!("{}", Sha256), "sha256");
        assert_eq!(format!("{}", Sha384), "sha384");
        assert_eq!(format!("{}", Sha512), "sha512");
        assert_eq!(format!("{}", Xxh3), "xxh3");
    }

    #[test]
    fn ordering() {
        let mut arr = [Sha1, Sha256, Sha384, Sha512, Xxh3];
        arr.sort_unstable();
        assert_eq!(arr, [Sha512, Sha384, Sha256, Sha1, Xxh3])
    }

    #[test]
    fn digest_lengths() {
        assert_eq!(Sha1.digest_len(), 20);
        assert_eq!(Sha256.digest_len(), 32);
        assert_eq!(Sha384.digest_len(), 48);
        assert_eq!(Sha512.digest_len(), 64);
        assert_eq!(Xxh3.digest_len(), 16);
    }
}
