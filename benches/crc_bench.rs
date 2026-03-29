use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use xfs_rs::crc::*;

fn bench_crc(c: &mut Criterion) {
    let sizes = [512, 1024, 4096, 16384, 65536];

    let mut group = c.benchmark_group("CRC32C");

    for size in sizes {
        let data = vec![0x42u8; size];

        // Benchmark: xfs_crc32c (using crc32c crate with PCLMULQDQ + SSE4.2)
        group.bench_with_input(
            BenchmarkId::new("xfs_crc32c", size),
            &data,
            |b, d| b.iter(|| xfs_crc32c(d))
        );
    }

    group.finish();
}

criterion_group!(benches, bench_crc);
criterion_main!(benches);