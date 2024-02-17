# `ssri2`

[![Cargo](https://img.shields.io/crates/v/ssri2.svg)](https://crates.io/crates/ssri2)
[![Documentation](https://docs.rs/ssri2/badge.svg)](https://docs.rs/ssri2)

[`ssri2`](https://github.com/cijiugechu/ssri2)(Standard Subresource
Integrity) is a Rust library for parsing, manipulating, serializing,
generating, and verifying [Subresource Integrity](https://w3c.github.io/webappsec/specs/subresourceintegrity/)
hashes.

## Example

Parse a string as [`Integrity`](struct.Integrity.html) to convert it to a struct:

```rust
use ssri2::Integrity;

let source = "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";

let parsed: Integrity = source.parse().unwrap();
assert_eq!(parsed.to_string(), source)
```

Generating a new hash from file data:

```rust
use ssri2::Integrity;

// By default, generates Integrity as Sha256.
// Use IntegrityOpts to pick the algorithm yourself.
let sri = Integrity::from(b"hello world");
assert_eq!(sri.to_string(), "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=");
```

Verifying data against an SRI:

```rust
use ssri2::{Integrity, Algorithm};

let sri = Integrity::from(b"hello world");
assert_eq!(sri.check(b"hello world").unwrap(), Algorithm::Sha256);
```

You can also use [`IntegrityOpts`](struct.IntegrityOpts.html) and [`IntegrityChecker`](struct.IntegrityChecker.html) to generate
and check subresource integrity, respectively. These allow things like multiple algorithms, and
incremental/streamed data input.

## Documentation

- [API Docs](https://docs.rs/ssri2)

## Features

- Parses and stringifies [Subresource Integrity](https://w3c.github.io/webappsec/specs/subresourceintegrity/) strings.
- Generates SRI strings from raw data.
- Strict standard compliance.
- Multiple entries for the same algorithm.

## License

This project is licensed under [the Apache-2.0 License](LICENSE.md).
