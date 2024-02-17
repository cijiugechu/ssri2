use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ssri2::Integrity;

const SOURCE: &str = "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";
const TEXT: &[u8] = b"hello world";
const SEG1: &[u8] = b"sha256-deadbeef";
const SEG2: &[u8] = b"sha256-badc0ffee";

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("parse", |b| {
        b.iter(|| {
            let _ = Integrity::from(black_box(SOURCE));
        })
    });

    c.bench_function("verify", |b| {
        b.iter(|| {
            let sri = Integrity::from(black_box(TEXT));
            let _ = sri.check(black_box(TEXT)).unwrap();
        })
    });

    c.bench_function("concat", |b| {
        b.iter(|| {
            let sri1 = Integrity::from(black_box(SEG1));
            let sri2 = Integrity::from(black_box(SEG2));
            let _ = sri1.concat(black_box(sri2));
        })
    });
}

criterion_group!(bench, criterion_benchmark);
criterion_main!(bench);
