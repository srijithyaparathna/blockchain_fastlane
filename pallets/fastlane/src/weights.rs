// ============================================================
// pallets/fastlane/src/weights.rs
// Weight definitions for the FastLane pallet.
//
// The values below are PLACEHOLDERS — sized as conservative
// upper bounds so the chain is not under-charging for these
// extrinsics. Replace with `cargo run --release --features
// runtime-benchmarks ... benchmark pallet` output before mainnet.
// ============================================================

#![allow(unused_parens)]

use frame_support::{traits::Get, weights::Weight};

pub trait WeightInfo {
    fn submit() -> Weight;
    fn attest() -> Weight;
    fn attest_unsigned() -> Weight;
    fn finalize() -> Weight;
    fn set_authorities(a: u32) -> Weight;
    fn set_threshold() -> Weight;
    fn post_bond() -> Weight;
    fn slash() -> Weight;
    fn on_initialize_expire(p: u32) -> Weight;
    fn on_initialize_finalize(p: u32) -> Weight;
}

/// Conservative placeholder weights. Read/write counts are accurate; the
/// per-call ref_time is intentionally generous (~50ms) so a non-benchmarked
/// chain does not under-price these extrinsics.
const READ: u64 = 25_000_000;
const WRITE: u64 = 100_000_000;
const VERIFY_SIG: u64 = 60_000_000;

pub struct SubstrateWeight<T>(core::marker::PhantomData<T>);

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn submit() -> Weight {
        Weight::from_parts(50_000_000, 0)
            .saturating_add(T::DbWeight::get().reads(4))
            .saturating_add(T::DbWeight::get().writes(4))
    }

    fn attest() -> Weight {
        Weight::from_parts(50_000_000 + VERIFY_SIG, 0)
            .saturating_add(T::DbWeight::get().reads(4))
            .saturating_add(T::DbWeight::get().writes(2))
    }

    fn attest_unsigned() -> Weight {
        Self::attest()
    }

    fn finalize() -> Weight {
        Weight::from_parts(30_000_000, 0)
            .saturating_add(T::DbWeight::get().reads(2))
            .saturating_add(T::DbWeight::get().writes(2))
    }

    fn set_authorities(a: u32) -> Weight {
        Weight::from_parts(20_000_000, 0)
            .saturating_add(Weight::from_parts(READ.saturating_mul(a as u64), 0))
            .saturating_add(T::DbWeight::get().reads(a as u64 + 1))
            .saturating_add(T::DbWeight::get().writes(1))
    }

    fn set_threshold() -> Weight {
        Weight::from_parts(15_000_000, 0)
            .saturating_add(T::DbWeight::get().reads(1))
            .saturating_add(T::DbWeight::get().writes(1))
    }

    fn post_bond() -> Weight {
        Weight::from_parts(40_000_000, 0)
            .saturating_add(T::DbWeight::get().reads(2))
            .saturating_add(T::DbWeight::get().writes(2))
    }

    fn slash() -> Weight {
        Weight::from_parts(50_000_000 + VERIFY_SIG, 0)
            .saturating_add(T::DbWeight::get().reads(4))
            .saturating_add(T::DbWeight::get().writes(3))
    }

    fn on_initialize_expire(p: u32) -> Weight {
        Weight::from_parts(10_000_000, 0)
            .saturating_add(Weight::from_parts(READ.saturating_mul(p as u64), 0))
            .saturating_add(T::DbWeight::get().reads(p as u64 + 1))
            .saturating_add(T::DbWeight::get().writes(p as u64))
    }

    fn on_initialize_finalize(p: u32) -> Weight {
        Weight::from_parts(10_000_000, 0)
            .saturating_add(Weight::from_parts(WRITE.saturating_mul(p as u64), 0))
            .saturating_add(T::DbWeight::get().reads(p as u64 + 1))
            .saturating_add(T::DbWeight::get().writes(p as u64))
    }
}

impl WeightInfo for () {
    fn submit() -> Weight { Weight::from_parts(50_000_000, 0) }
    fn attest() -> Weight { Weight::from_parts(110_000_000, 0) }
    fn attest_unsigned() -> Weight { Weight::from_parts(110_000_000, 0) }
    fn finalize() -> Weight { Weight::from_parts(30_000_000, 0) }
    fn set_authorities(_: u32) -> Weight { Weight::from_parts(50_000_000, 0) }
    fn set_threshold() -> Weight { Weight::from_parts(15_000_000, 0) }
    fn post_bond() -> Weight { Weight::from_parts(40_000_000, 0) }
    fn slash() -> Weight { Weight::from_parts(110_000_000, 0) }
    fn on_initialize_expire(_: u32) -> Weight { Weight::from_parts(10_000_000, 0) }
    fn on_initialize_finalize(_: u32) -> Weight { Weight::from_parts(10_000_000, 0) }
}
