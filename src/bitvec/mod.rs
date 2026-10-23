use serde::{Deserialize, Serialize};

// bits per storage block; the bit array is packed into u64 words
const BITS_PER_BLOCK: u64 = u64::BITS as u64;

// bit array packed into u64 chunks, the backing storage for the bloom filter.
// deserialization goes through BitVecWire so a remote peer can never hand us a
// length that disagrees with the number of blocks (which would index out of bounds)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BitVecWire")]
pub struct BitVec {
    bits: Vec<u64>,
    len: u64,
}

#[derive(Deserialize)]
struct BitVecWire {
    bits: Vec<u64>,
    len: u64,
}

impl TryFrom<BitVecWire> for BitVec {
    type Error = String;

    fn try_from(wire: BitVecWire) -> Result<Self, Self::Error> {
        let expected = wire.len.div_ceil(BITS_PER_BLOCK);
        if wire.bits.len() as u64 != expected {
            return Err(format!(
                "bitvec has {} blocks, len {} needs {}",
                wire.bits.len(),
                wire.len,
                expected
            ));
        }
        Ok(BitVec {
            bits: wire.bits,
            len: wire.len,
        })
    }
}

impl BitVec {
    pub fn new(len: u64) -> Self {
        BitVec {
            bits: vec![0; len.div_ceil(BITS_PER_BLOCK) as usize],
            len,
        }
    }

    // returns false (and sets nothing) when the index is out of range
    pub fn set(&mut self, index: u64) -> bool {
        if index >= self.len {
            return false;
        }
        self.bits[(index / BITS_PER_BLOCK) as usize] |= 1 << (index % BITS_PER_BLOCK);
        true
    }

    // out of range reads as unset
    pub fn get(&self, index: u64) -> bool {
        if index >= self.len {
            return false;
        }
        (self.bits[(index / BITS_PER_BLOCK) as usize] >> (index % BITS_PER_BLOCK)) & 1 == 1
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get() {
        let mut bits = BitVec::new(130);
        assert!(bits.set(0));
        assert!(bits.set(64));
        assert!(bits.set(129));
        assert!(bits.get(0) && bits.get(64) && bits.get(129));
        assert!(!bits.get(1) && !bits.get(63) && !bits.get(128));
        assert_eq!((0..130).filter(|&i| bits.get(i)).count(), 3);
    }

    #[test]
    fn test_out_of_range_is_harmless() {
        let mut bits = BitVec::new(10);
        assert!(!bits.set(10));
        assert!(!bits.get(10));
        assert!(!bits.get(u64::MAX));
        assert!(bits.bits.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_block_count() {
        assert_eq!(BitVec::new(0).bits.len(), 0);
        assert_eq!(BitVec::new(1).bits.len(), 1);
        assert_eq!(BitVec::new(64).bits.len(), 1);
        assert_eq!(BitVec::new(65).bits.len(), 2);
    }

    #[test]
    fn test_round_trip() {
        let mut bits = BitVec::new(100);
        bits.set(42);
        let bytes = bincode::serialize(&bits).unwrap();
        let back: BitVec = bincode::deserialize(&bytes).unwrap();
        assert_eq!(bits, back);
    }

    #[test]
    fn test_rejects_len_block_mismatch() {
        // 1 block claiming 1000 bits
        let forged = (vec![0u64], 1000u64);
        let bytes = bincode::serialize(&forged).unwrap();
        assert!(bincode::deserialize::<BitVec>(&bytes).is_err());
    }
}
