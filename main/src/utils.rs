#[macro_use]
mod code_align;
mod recorders;
pub use recorders::*;
mod progressbar;
pub use progressbar::*;
mod logging;
pub use logging::*;
mod threadding;
pub use threadding::*;

use std::{
    convert::TryInto,
    fmt::{Debug, UpperHex},
};

pub trait StrErr<T, E> {
    fn strerr(self) -> Result<T, String>;
}

impl<T, E> StrErr<T, E> for Result<T, E>
where
    E: Debug,
{
    fn strerr(self) -> Result<T, String> {
        self.map_err(|err| format!("{:?}", err))
    }
}

pub struct MutBit<'a> {
    byte: &'a mut u8,
    local_bit: u8,
}

impl<'a> MutBit<'a> {
    pub fn get(&self) -> bool {
        *self.byte & (1 << self.local_bit) != 0
    }

    #[allow(dead_code)]
    pub fn set(&mut self, val: bool) {
        let change = self.get() ^ val;
        *self.byte ^= (change as u8) << self.local_bit;
    }

    pub fn flip(&mut self) {
        *self.byte ^= 1 << self.local_bit;
    }
}

pub fn mutbit(bytes: &mut [u8], bitnum: u64) -> Result<MutBit, String> {
    let bitnum: usize = bitnum.try_into().unwrap();
    let bytenum = bitnum / 8;
    let local_bit = (bitnum % 8) as u8;
    match bytes.len() {
        l if l > bytenum => Ok(MutBit {
            byte: &mut bytes[bytenum],
            local_bit,
        }),
        l => Err(format!(
            "Bitnum {} out of bounds in array of {}*8={} bits",
            bitnum,
            l,
            l * 8
        )),
    }
}

pub trait ToFullHex {
    fn to_full_hex(&self, zero_x: bool) -> String;
}

impl<T> ToFullHex for T
where
    T: UpperHex,
{
    fn to_full_hex(&self, zero_x: bool) -> String {
        let octets = std::mem::size_of_val(self) * 2;
        if zero_x {
            format!("{:#0width$X}", self, width = octets + 2)
        } else {
            format!("{:0width$X}", self, width = octets)
        }
    }
}

mod test {
    #![cfg(test)]

    use super::mutbit;

    #[test]
    pub fn test_mutbit() {
        let mut actual = [0b0000_1100u8, 0b0000_0010u8];
        let expect = [0b0000_0101u8, 0b0000_0100u8];

        let mut bit = mutbit(&mut actual, 0).unwrap();
        assert!(!bit.get());
        bit.set(true); // change from 0 to 1
        assert!(bit.get());

        let mut bit = mutbit(&mut actual, 1).unwrap();
        assert!(!bit.get());
        bit.set(false); // change from 0 to 0
        assert!(!bit.get());

        let mut bit = mutbit(&mut actual, 2).unwrap();
        assert!(bit.get());
        bit.set(true); // change from 1 to 1
        assert!(bit.get());

        let mut bit = mutbit(&mut actual, 3).unwrap();
        assert!(bit.get());
        bit.set(false); // change from 1 to 0
        assert!(!bit.get());

        let mut bit = mutbit(&mut actual, 9).unwrap();
        assert!(bit.get());
        bit.flip(); // flip from 1 to 0
        assert!(!bit.get());

        let mut bit = mutbit(&mut actual, 10).unwrap();
        assert!(!bit.get());
        bit.flip(); // flip from 0 to 1
        assert!(bit.get());

        // Out of bounds should return an error
        assert!(mutbit(&mut actual, 16).is_err());

        assert_eq!(actual, expect);
    }
}
