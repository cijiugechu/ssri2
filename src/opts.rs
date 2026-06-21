use std::fmt;

use crate::algorithm::Algorithm;
use crate::errors::Error;
use crate::hash::Hash;
use crate::integrity::Integrity;

use digest::Digest as DigestTrait;

/**
Builds a new [`Integrity`] with one or more algorithms and incremental input.

# Examples

```
use ssri2::{Algorithm, IntegrityBuilder};

let sri = IntegrityBuilder::new()
    .algorithm(Algorithm::Sha512)
    .algorithm(Algorithm::Sha256)
    .chain(b"hello world")
    .finish()
    .unwrap();

assert_eq!(sri.strongest_algorithm(), Algorithm::Sha512);
```
*/
#[derive(Clone, Default)]
pub struct IntegrityBuilder {
    sha1: Option<sha1::Sha1>,
    sha256: Option<sha2::Sha256>,
    sha384: Option<sha2::Sha384>,
    sha512: Option<sha2::Sha512>,
    xxh3: Option<xxhash_rust::xxh3::Xxh3>,
    disturbed: bool,
}

impl fmt::Debug for IntegrityBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntegrityBuilder")
            .field("sha1", &self.sha1.is_some())
            .field("sha256", &self.sha256.is_some())
            .field("sha384", &self.sha384.is_some())
            .field("sha512", &self.sha512.is_some())
            .field("xxh3", &self.xxh3.is_some())
            .field("disturbed", &self.disturbed)
            .finish()
    }
}

impl IntegrityBuilder {
    /// Create an empty integrity builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable an algorithm.
    ///
    /// # Panics
    ///
    /// Panics if called after input has already been added.
    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        if self.disturbed {
            panic!("cannot add new algorithms after input has been added");
        }

        match algorithm {
            Algorithm::Sha1 => self.sha1 = Some(sha1::Sha1::new()),
            Algorithm::Sha256 => self.sha256 = Some(sha2::Sha256::new()),
            Algorithm::Sha384 => self.sha384 = Some(sha2::Sha384::new()),
            Algorithm::Sha512 => self.sha512 = Some(sha2::Sha512::new()),
            Algorithm::Xxh3 => self.xxh3 = Some(xxhash_rust::xxh3::Xxh3::new()),
        }

        self
    }

    /// Add bytes to all configured hashers.
    pub fn update<B: AsRef<[u8]>>(&mut self, input: B) {
        let input = input.as_ref();
        self.disturbed = true;

        if let Some(hasher) = &mut self.sha1 {
            DigestTrait::update(hasher, input);
        }
        if let Some(hasher) = &mut self.sha256 {
            DigestTrait::update(hasher, input);
        }
        if let Some(hasher) = &mut self.sha384 {
            DigestTrait::update(hasher, input);
        }
        if let Some(hasher) = &mut self.sha512 {
            DigestTrait::update(hasher, input);
        }
        if let Some(hasher) = &mut self.xxh3 {
            hasher.update(input);
        }
    }

    /// Add bytes to all configured hashers and return `self` for chaining.
    pub fn chain<B: AsRef<[u8]>>(mut self, input: B) -> Self {
        self.update(input);
        self
    }

    /// Reset configured hashers back to their initial state.
    pub fn reset(&mut self) {
        if self.sha1.is_some() {
            self.sha1 = Some(sha1::Sha1::new());
        }
        if self.sha256.is_some() {
            self.sha256 = Some(sha2::Sha256::new());
        }
        if self.sha384.is_some() {
            self.sha384 = Some(sha2::Sha384::new());
        }
        if self.sha512.is_some() {
            self.sha512 = Some(sha2::Sha512::new());
        }
        if self.xxh3.is_some() {
            self.xxh3 = Some(xxhash_rust::xxh3::Xxh3::new());
        }
        self.disturbed = false;
    }

    /// Finish hashing and return a compact [`Integrity`] value.
    pub fn finish(self) -> Result<Integrity, Error> {
        let mut hashes = Vec::with_capacity(5);

        if let Some(hasher) = self.sha512 {
            hashes.push(Hash::from_algorithm_digest(
                Algorithm::Sha512,
                hasher.finalize(),
            )?);
        }
        if let Some(hasher) = self.sha384 {
            hashes.push(Hash::from_algorithm_digest(
                Algorithm::Sha384,
                hasher.finalize(),
            )?);
        }
        if let Some(hasher) = self.sha256 {
            hashes.push(Hash::from_algorithm_digest(
                Algorithm::Sha256,
                hasher.finalize(),
            )?);
        }
        if let Some(hasher) = self.sha1 {
            hashes.push(Hash::from_algorithm_digest(
                Algorithm::Sha1,
                hasher.finalize(),
            )?);
        }
        if let Some(hasher) = self.xxh3 {
            hashes.push(Hash::from_algorithm_digest(
                Algorithm::Xxh3,
                hasher.digest128().to_be_bytes(),
            )?);
        }

        Integrity::from_ordered_hashes(hashes)
    }
}

impl digest::Update for IntegrityBuilder {
    fn update(&mut self, data: &[u8]) {
        IntegrityBuilder::update(self, data);
    }

    fn chain(self, input: impl AsRef<[u8]>) -> Self {
        IntegrityBuilder::chain(self, input)
    }
}

impl digest::Reset for IntegrityBuilder {
    fn reset(&mut self) {
        IntegrityBuilder::reset(self)
    }
}

impl std::io::Write for IntegrityBuilder {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Algorithm;
    use super::Error;
    use super::IntegrityBuilder;

    #[test]
    fn basic_test() {
        let result = IntegrityBuilder::new()
            .algorithm(Algorithm::Sha1)
            .algorithm(Algorithm::Sha256)
            .chain(b"hello world")
            .finish()
            .unwrap();
        assert_eq!(
            result.to_string(),
            "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek= sha1-Kq5sNclPz7QV2+lfQIuc6R7oRu0="
        )
    }

    #[test]
    fn no_algorithms() {
        assert_eq!(IntegrityBuilder::new().finish(), Err(Error::NoAlgorithms));
    }

    #[test]
    fn write_test() {
        use std::io::Write;

        let mut builder = IntegrityBuilder::new()
            .algorithm(Algorithm::Sha1)
            .algorithm(Algorithm::Sha256);
        let size = builder.write(b"hello ").expect("failed to write bytes");
        assert_eq!(6, size);
        let size = builder.write(b"world").expect("failed to write bytes");
        assert_eq!(5, size);
        assert_eq!(
            builder.finish().unwrap().to_string(),
            "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek= sha1-Kq5sNclPz7QV2+lfQIuc6R7oRu0="
        )
    }
}
