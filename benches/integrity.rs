use std::hint::black_box;
use std::sync::LazyLock;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ssri2::{Algorithm, Integrity, IntegrityChecker, IntegrityOpts};

const TEXT_SMALL: &[u8] = b"hello world";
const TEXT_MISMATCH: &[u8] = b"goodbye world";
const HEX_SHA256_SMALL: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
const UNKNOWN_ALGORITHM: &str = "sha999-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";
const INVALID_BASE64: &str = "sha256-not-valid!!!";
const INVALID_DIGEST_LENGTH: &str = "sha256-pc6cFV7Qk5dhRkbJcX/HzZSxAj17drYY1Ank";

static TEXT_4K: LazyLock<Vec<u8>> = LazyLock::new(|| vec![b'a'; 4 * 1024]);
static TEXT_1MIB: LazyLock<Vec<u8>> = LazyLock::new(|| vec![b'z'; 1024 * 1024]);

static SRI_SMALL: LazyLock<Integrity> = LazyLock::new(|| Integrity::from(TEXT_SMALL));
static SRI_4K: LazyLock<Integrity> = LazyLock::new(|| Integrity::from(TEXT_4K.as_slice()));
static SRI_1MIB: LazyLock<Integrity> = LazyLock::new(|| Integrity::from(TEXT_1MIB.as_slice()));

static SINGLE_SHA256: LazyLock<String> = LazyLock::new(|| SRI_SMALL.to_string());
static MULTI_HASH: LazyLock<String> = LazyLock::new(|| {
    IntegrityOpts::new()
        .algorithm(Algorithm::Sha512)
        .algorithm(Algorithm::Sha384)
        .algorithm(Algorithm::Sha256)
        .chain(TEXT_SMALL)
        .result()
        .to_string()
});
static SPACED_HASH: LazyLock<String> =
    LazyLock::new(|| format!(" \n  {} \t", SINGLE_SHA256.as_str()));
static CONCAT_RIGHT: LazyLock<Integrity> = LazyLock::new(|| Integrity::from(TEXT_MISMATCH));
static MATCH_MULTI: LazyLock<Integrity> = LazyLock::new(|| {
    IntegrityOpts::new()
        .algorithm(Algorithm::Sha512)
        .algorithm(Algorithm::Sha256)
        .chain(TEXT_SMALL)
        .result()
});

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse");

    for (name, input) in [
        ("single_sha256", SINGLE_SHA256.as_str()),
        ("multi_hash", MULTI_HASH.as_str()),
        ("spaced_hash", SPACED_HASH.as_str()),
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(name), input, |b, input| {
            b.iter(|| black_box(input).parse::<Integrity>().unwrap());
        });
    }

    group.bench_with_input(
        BenchmarkId::from_parameter("unknown_algorithm"),
        UNKNOWN_ALGORITHM,
        |b, input| {
            b.iter(|| black_box(input).parse::<Integrity>().unwrap_err());
        },
    );
    group.bench_with_input(
        BenchmarkId::from_parameter("invalid_base64"),
        INVALID_BASE64,
        |b, input| {
            b.iter(|| black_box(input).parse::<Integrity>().unwrap_err());
        },
    );
    group.bench_with_input(
        BenchmarkId::from_parameter("invalid_digest_length"),
        INVALID_DIGEST_LENGTH,
        |b, input| {
            b.iter(|| black_box(input).parse::<Integrity>().unwrap_err());
        },
    );

    group.finish();
}

fn bench_generate(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate");

    group.throughput(Throughput::Bytes(TEXT_SMALL.len() as u64));
    group.bench_function(BenchmarkId::new("sha256", "small"), |b| {
        b.iter(|| Integrity::from(black_box(TEXT_SMALL)));
    });
    group.bench_function(BenchmarkId::new("sha256_sha512", "small"), |b| {
        b.iter(|| {
            IntegrityOpts::new()
                .algorithm(Algorithm::Sha256)
                .algorithm(Algorithm::Sha512)
                .chain(black_box(TEXT_SMALL))
                .result()
        });
    });

    group.throughput(Throughput::Bytes(TEXT_4K.len() as u64));
    group.bench_function(BenchmarkId::new("sha256", "4KiB"), |b| {
        b.iter(|| Integrity::from(black_box(TEXT_4K.as_slice())));
    });
    group.bench_function(BenchmarkId::new("sha256_sha512", "4KiB"), |b| {
        b.iter(|| {
            IntegrityOpts::new()
                .algorithm(Algorithm::Sha256)
                .algorithm(Algorithm::Sha512)
                .chain(black_box(TEXT_4K.as_slice()))
                .result()
        });
    });

    group.throughput(Throughput::Bytes(TEXT_1MIB.len() as u64));
    group.bench_function(BenchmarkId::new("sha256", "1MiB"), |b| {
        b.iter(|| Integrity::from(black_box(TEXT_1MIB.as_slice())));
    });
    group.bench_function(BenchmarkId::new("sha256_sha512", "1MiB"), |b| {
        b.iter(|| {
            IntegrityOpts::new()
                .algorithm(Algorithm::Sha256)
                .algorithm(Algorithm::Sha512)
                .chain(black_box(TEXT_1MIB.as_slice()))
                .result()
        });
    });

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");

    group.throughput(Throughput::Bytes(TEXT_SMALL.len() as u64));
    group.bench_function(BenchmarkId::new("success", "small"), |b| {
        b.iter(|| SRI_SMALL.check(black_box(TEXT_SMALL)).unwrap());
    });
    group.bench_function(BenchmarkId::new("mismatch", "small"), |b| {
        b.iter(|| SRI_SMALL.check(black_box(TEXT_MISMATCH)).unwrap_err());
    });
    group.bench_function(BenchmarkId::new("multi_hash_success", "small"), |b| {
        b.iter(|| MATCH_MULTI.check(black_box(TEXT_SMALL)).unwrap());
    });

    group.throughput(Throughput::Bytes(TEXT_4K.len() as u64));
    group.bench_function(BenchmarkId::new("success", "4KiB"), |b| {
        b.iter(|| SRI_4K.check(black_box(TEXT_4K.as_slice())).unwrap());
    });
    group.bench_function(BenchmarkId::new("streaming_success", "4KiB"), |b| {
        b.iter(|| {
            let mut checker = IntegrityChecker::new(SRI_4K.clone());
            for chunk in TEXT_4K.chunks(512) {
                checker.input(black_box(chunk));
            }
            checker.result().unwrap()
        });
    });

    group.throughput(Throughput::Bytes(TEXT_1MIB.len() as u64));
    group.bench_function(BenchmarkId::new("success", "1MiB"), |b| {
        b.iter(|| SRI_1MIB.check(black_box(TEXT_1MIB.as_slice())).unwrap());
    });

    group.finish();
}

fn bench_conversions(c: &mut Criterion) {
    let mut group = c.benchmark_group("conversions");

    group.bench_function("from_hex_sha256", |b| {
        b.iter(|| Integrity::from_hex(black_box(HEX_SHA256_SMALL), Algorithm::Sha256).unwrap());
    });
    group.bench_function("to_hex_sha256", |b| {
        b.iter(|| black_box(SRI_SMALL.to_hex()));
    });
    group.bench_function("display_single_sha256", |b| {
        b.iter(|| black_box(SRI_SMALL.to_string()));
    });
    group.bench_function("display_multi_hash", |b| {
        b.iter(|| black_box(MATCH_MULTI.to_string()));
    });

    group.finish();
}

fn bench_concat_matches(c: &mut Criterion) {
    let mut group = c.benchmark_group("concat_matches");

    group.bench_function("concat_distinct_sha256", |b| {
        b.iter(|| SRI_SMALL.clone().concat(black_box(CONCAT_RIGHT.clone())));
    });
    group.bench_function("concat_duplicate_sha256", |b| {
        b.iter(|| SRI_SMALL.clone().concat(black_box(SRI_SMALL.clone())));
    });
    group.bench_function("matches_multi_hash", |b| {
        b.iter(|| black_box(MATCH_MULTI.matches(&SRI_SMALL)));
    });

    group.finish();
}

pub fn criterion_benchmark(c: &mut Criterion) {
    bench_parse(c);
    bench_generate(c);
    bench_verify(c);
    bench_conversions(c);
    bench_concat_matches(c);
}

criterion_group!(bench, criterion_benchmark);
criterion_main!(bench);
