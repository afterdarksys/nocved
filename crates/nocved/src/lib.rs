//! nocved: continuous host behaviour sensor. See DESIGN.md.

pub mod config;
pub mod daemon;
pub mod feed;
pub mod fsutil;
pub mod notify;
pub mod procfs;
pub mod ship;
pub mod sources;
pub mod spool;

#[cfg(any(test, feature = "testutil"))]
pub mod testutil;
