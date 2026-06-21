# `ssri2`

[![Cargo](https://img.shields.io/crates/v/ssri2.svg)](https://crates.io/crates/ssri2)
[![Documentation](https://docs.rs/ssri2/badge.svg)](https://docs.rs/ssri2)

[`ssri2`](https://github.com/cijiugechu/ssri2) (Standard Subresource
Integrity) is a Rust library for parsing, manipulating, serializing,
generating, and verifying [Subresource Integrity](https://w3c.github.io/webappsec/specs/subresourceintegrity/)
hashes.


## Examples

Parse a strict SRI string:

```rust
use ssri2::Integrity;

let source = "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";

let parsed: Integrity = source.parse().unwrap();
assert_eq!(parsed.to_string(), source)
```

Generate a single digest from data:

```rust
use ssri2::{Algorithm, Integrity};

let sri = Integrity::digest(b"hello world", Algorithm::Sha256);
assert_eq!(sri.to_string(), "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=");
```

Generate multiple digests:

```rust
use ssri2::{Algorithm, IntegrityBuilder};

let sri = IntegrityBuilder::new()
    .algorithm(Algorithm::Sha512)
    .algorithm(Algorithm::Sha256)
    .chain(b"hello world")
    .finish()
    .unwrap();

assert_eq!(sri.strongest_algorithm(), Algorithm::Sha512);
```

Verify data against an SRI:

```rust
use ssri2::{Integrity, Algorithm};

let sri = Integrity::digest(b"hello world", Algorithm::Sha256);
assert_eq!(sri.verify(b"hello world").unwrap().algorithm, Algorithm::Sha256);
```

Stream verification:

```rust
use ssri2::{Algorithm, Integrity};

let sri = Integrity::digest(b"hello world", Algorithm::Sha256);
let mut checker = sri.checker();
checker.update(b"hello ");
checker.update(b"world");

assert_eq!(checker.finish().unwrap().matched_index, 0);
```

Inspect digest bytes without accessing internal storage:

```rust
use ssri2::{Algorithm, Integrity};

let sri = Integrity::digest(b"hello world", Algorithm::Sha256);
let digest = sri.first();

assert_eq!(digest.algorithm(), Algorithm::Sha256);
assert_eq!(
    digest.to_hex(),
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
);
```

## Documentation

- [API Docs](https://docs.rs/ssri2)

## Features

- Parses and stringifies [Subresource Integrity](https://w3c.github.io/webappsec/specs/subresourceintegrity/) strings.
- Generates SRI strings from raw data.
- Strict parsing with base64 validation and algorithm-specific digest length checks.
- Data-oriented internal representation with a single-digest fast path.
- Borrowed digest views through `DigestRef`.
- Streaming verification through `Checker`.
- Multiple entries for the same algorithm.
- First-class `sha1` and `xxh3` support for non-browser package-integrity use cases.

## License

This project is licensed under [the Apache-2.0 License](LICENSE.md).
