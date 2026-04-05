use std::ops::{BitOrAssign, Shr, Shl, BitAnd};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitVec<T = u64> {
    bits: Vec<T>,
    len: u64
}

impl<T: Default + Clone + From<u8> + Shl<u64> + BitOrAssign<<T as Shl<u64>>::Output> + Shr<u64>> BitVec<T> {
    pub fn new(len: u64) -> Self {
        let bits_per_block = (std::mem::size_of::<T>() * 8) as u64; // bits required per block
        let num_blocks = ((len + bits_per_block - 1) / bits_per_block) as usize;  // ceiling division
        
        BitVec {
            bits: vec![T::default(); num_blocks],
            len,
        }
    }
    
    pub fn set(&mut self, index: u64) {
        assert!(index < self.len, "index out of bounds");
         
        let bits_per_block = (std::mem::size_of::<T>() * 8) as u64;
        let block = (index / bits_per_block) as usize;
        let bit = index % bits_per_block;
        self.bits[block] |= T::from(1u8) << bit;
    }
    
    pub fn get(&self, index: u64) -> bool where <T as Shr<u64>>::Output: BitAnd<T>, <<T as Shr<u64>>::Output as BitAnd<T>>::Output: PartialEq<T>  {
        assert!(index < self.len, "index out of bounds");
        
        let bits_per_block = (std::mem::size_of::<T>() * 8) as u64;
        let block = (index / bits_per_block) as usize;
        let bit = index % bits_per_block;
        (self.bits[block].clone() >> bit) & T::from(1u8) != T::default()
    }
    
    pub fn len(&self) -> u64 {
        self.len
    }
}