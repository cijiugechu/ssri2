/*!
[`ssri2`](https://github.com/cijiugechu/ssri2), short for Standard Subresource
Integrity, is a Rust library for parsing, manipulating, serializing,
generating, and verifying [Subresource Integrity](https://w3c.github.io/webappsec/specs/subresourceintegrity/)
hashes.

# Examples

Parse a string as [`Integrity`](struct.Integrity.html) to convert it to a struct:
```
# use ssri2::Integrity;
let source = "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";

let parsed: Integrity = source.parse().unwrap();
assert_eq!(parsed.to_string(), source)
```

Generating a new hash from file data:
```
# use ssri2::{Algorithm, Integrity};
let sri = Integrity::digest(b"hello world", Algorithm::Sha256);
assert_eq!(sri.to_string(), "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=");
```

Verifying data against an SRI:
```
# use ssri2::{Integrity, Algorithm};
let sri = Integrity::digest(b"hello world", Algorithm::Sha256);
assert_eq!(sri.verify(b"hello world").unwrap().algorithm, Algorithm::Sha256);
```

Use [`IntegrityBuilder`](struct.IntegrityBuilder.html) and [`Checker`](struct.Checker.html)
for multiple algorithms and incremental/streamed data input.
*/

mod algorithm;
mod checker;
mod errors;
mod hash;
mod integrity;
mod opts;

pub use algorithm::Algorithm::{self, *};
pub use checker::{Checker, Verification};
pub use errors::Error;
pub use integrity::{DigestRef, Integrity};
pub use opts::IntegrityBuilder;
