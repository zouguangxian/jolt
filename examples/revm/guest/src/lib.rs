#![cfg_attr(feature = "guest", no_std)]

use revm::{Context, MainContext, MainBuilder};

#[jolt::provable]
fn exec(n: u32) {
    let revm = Context::mainnet().build_mainnet();
}
