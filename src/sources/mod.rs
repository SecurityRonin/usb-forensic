//! Reader-crate adapters: pure mappings from each fleet reader's already-decoded
//! output into the source-agnostic `Claim` model.

pub mod apple_ipod;
pub mod device_image;
pub mod emdmgmt;
pub mod jumplist;
pub mod lnk;
pub mod mountpoints2;
pub mod partition_diag;
pub mod peripheral;
pub mod volume_cache;
