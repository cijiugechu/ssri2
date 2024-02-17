use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ssri2::Integrity;

const SOURCE: &str = "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";
const TEXT: &[u8] = b"hello world";

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
}

criterion_group!(bench, criterion_benchmark);
criterion_main!(bench);
