// HELIOS-NET :: rust-core/src/pathfinder.rs
// Production-ready A* Pathfinding Engine with Multi-Factor Risk Scoring and C-Compatible FFI.

#![allow(clippy::all)]

use std::collections::{BinaryHeap, HashMap};
use std::cmp::Ordering;
use std::os::raw::{c_char, c_double, c_int};
use std::ffi::{CStr, CString};
use std::ptr;