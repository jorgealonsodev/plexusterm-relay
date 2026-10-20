//! Sans-IO engines for both ends of a PlexusTerm share.
//!
//! [`sharer::SharerEngine`] is the reference for the sharing side PlexusTerm
//! builds; [`viewer::ViewerEngine`] is the
//! logic the web viewer mirrors. Neither does any IO: callers feed relay
//! messages in and send the returned messages out.

pub mod sharer;
pub mod snapshot;
pub mod viewer;
