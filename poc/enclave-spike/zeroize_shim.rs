//! Std-only stand-in for the `zeroize` crate, enough to compile the shipped
//! `AppleSecureElement` module in the offline FFI verifier. Built as an rlib and passed
//! via `--extern zeroize=`. Real zeroize-on-drop is a crate concern, not an FFI concern.
#![crate_name = "zeroize"]

use std::ops::{Deref, DerefMut};

pub struct Zeroizing<T>(T);
impl<T> Zeroizing<T> {
    pub fn new(v: T) -> Self { Zeroizing(v) }
}
impl<T> Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T { &self.0 }
}
impl<T> DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T { &mut self.0 }
}
