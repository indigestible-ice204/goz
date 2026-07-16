//! Name-arena compaction benchmark: how long do queries actually stay blocked?
//!
//! Compaction rebuilds both name arenas. It used to run inline inside
//! `apply_batch`, under the index write lock, so its whole cost was time every
//! query on the volume spent blocked.
//!
//! It is now split: [`VolumeIndex::plan_compaction`] takes `&self` and does the
//! copying (the expensive part) while queries keep reading, and
//! [`VolumeIndex::apply_compaction`] takes `&mut self` and only writes columns.
//! Only the second half blocks anyone.
//!
//! `plan` + `install` should sum to roughly the old inline cost. The number that
//! matters is `install` on its own, because that is the new stall.
//!
//! Run with `cargo bench -p goz-core --bench compact`.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use criterion::{Criterion, criterion_group, criterion_main};
use goz_core::index::{FrnMap, NTFS_ROOT_FRN, VolumeIndex};
use goz_core::types::Frn;
use goz_core::usn::record::{
    FILE_ATTRIBUTE_DIRECTORY, ParsedUsnRecord, USN_REASON_FILE_CREATE, USN_REASON_FILE_DELETE,
    USN_REASON_RENAME_NEW_NAME,
};
use std::hint::black_box;

const L1: u64 = 20;
const L2: u64 = 14;
const L3: u64 = 12;
const FILES_PER_LEAF: u64 = 60; // ~200k files, enough to make the copy real

fn frn(rec: u64) -> Frn {
    Frn(rec | (1u64 << 48))
}

fn rec(f: Frn, parent: Frn, name: &str, is_dir: bool, reason: u32) -> ParsedUsnRecord {
    ParsedUsnRecord {
        major_version: 2,
        frn: f,
        parent_frn: parent,
        usn: 0,
        timestamp_ft: 0,
        reason,
        attributes: if is_dir { FILE_ATTRIBUTE_DIRECTORY } else { 0 },
        name: name.as_bytes().to_vec(),
        name_lossy: false,
    }
}

/// A realistic index with enough garbage in the arenas that a compaction is
/// actually warranted: every third file is renamed (leaving its old name dead)
/// and every seventh is deleted.
fn dirty_index() -> VolumeIndex {
    let mut idx = VolumeIndex::new(NTFS_ROOT_FRN, FrnMap::sparse());
    let mut next: u64 = 1000;
    let mut files: Vec<Frn> = Vec::new();

    for a in 0..L1 {
        let d1 = frn(next);
        next += 1;
        idx.insert_enum(&rec(
            d1,
            NTFS_ROOT_FRN,
            &format!("amd64_microsoft-windows-component-{a:03}_31bf3856ad364e35_none_deadbeef"),
            true,
            USN_REASON_FILE_CREATE,
        ));
        for b in 0..L2 {
            let d2 = frn(next);
            next += 1;
            idx.insert_enum(&rec(
                d2,
                d1,
                &format!("subcomponent_{b:03}_none_cafef00dbaadf00d"),
                true,
                USN_REASON_FILE_CREATE,
            ));
            for c in 0..L3 {
                let d3 = frn(next);
                next += 1;
                idx.insert_enum(&rec(
                    d3,
                    d2,
                    &format!("leaf_{c:03}_e1a2b3c4d5f60718"),
                    true,
                    USN_REASON_FILE_CREATE,
                ));
                for _ in 0..FILES_PER_LEAF {
                    let file = frn(next);
                    next += 1;
                    // Globally unique name: names are interned, so only a name
                    // whose LAST reference drops leaves garbage behind. A name
                    // repeated in every leaf would survive all the churn below
                    // and the fixture would (correctly) never warrant a
                    // compaction.
                    idx.insert_enum(&rec(
                        file,
                        d3,
                        &format!("component-payload-{next:07}-9f8e7d6c5b4a3210.dll"),
                        false,
                        USN_REASON_FILE_CREATE,
                    ));
                    files.push(file);
                }
            }
        }
    }

    // Churn: renames leave the old name dead in the arena, deletes tombstone a
    // whole chain. This is what makes the arenas worth compacting.
    let mut batch = Vec::new();
    for (i, &f) in files.iter().enumerate() {
        if i % 3 == 0 {
            batch.push(rec(
                f,
                NTFS_ROOT_FRN,
                &format!("renamed-payload-{i:07}-0123456789abcdef.dll"),
                false,
                USN_REASON_RENAME_NEW_NAME,
            ));
        } else if i % 7 == 0 {
            batch.push(rec(f, NTFS_ROOT_FRN, "", false, USN_REASON_FILE_DELETE));
        }
        if batch.len() >= 4096 {
            idx.apply_batch(&batch);
            batch.clear();
        }
    }
    if !batch.is_empty() {
        idx.apply_batch(&batch);
    }
    idx
}

fn bench_compact(c: &mut Criterion) {
    let idx = dirty_index();
    assert!(
        idx.plan_compaction().is_some(),
        "fixture must be dirty enough to warrant a compaction, or this measures nothing"
    );

    let mut g = c.benchmark_group("compact_200k");
    g.sample_size(10);

    // The expensive half. Runs while queries keep reading: NOT a stall.
    g.bench_function("plan (concurrent with queries)", |b| {
        b.iter(|| black_box(idx.plan_compaction()));
    });

    // The half that holds the exclusive lock. THIS is the query stall, and the
    // whole point of the split is that it is only column writes.
    g.bench_function("install (blocks queries)", |b| {
        b.iter_batched(
            || {
                let fresh = dirty_index();
                let plan = fresh.plan_compaction().expect("dirty");
                (fresh, plan)
            },
            |(mut fresh, plan)| fresh.apply_compaction(black_box(plan)),
            criterion::BatchSize::LargeInput,
        );
    });

    // What the old inline path cost: plan + install together, all of it under
    // the write lock.
    g.bench_function("plan+install (the old inline stall)", |b| {
        b.iter_batched(
            dirty_index,
            |mut fresh| {
                let plan = fresh.plan_compaction().expect("dirty");
                fresh.apply_compaction(black_box(plan));
            },
            criterion::BatchSize::LargeInput,
        );
    });

    g.finish();
}

criterion_group!(benches, bench_compact);
criterion_main!(benches);
