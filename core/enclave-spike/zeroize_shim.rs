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
