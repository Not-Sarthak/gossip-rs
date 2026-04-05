use std::{hash::Hasher, marker::PhantomData};
use fnv::FnvHasher;
use std::ops::{BitAnd, BitOrAssign, Shl, Shr};
use crate::bitvec::BitVec;

#[derive(Debug, Clone)]
pub struct Bloom<T> {
    pub seed: Vec<u64>,
    pub bloom_filter: BitVec<T>,
    counter: u64,
    _phantom: PhantomData<T>
}

impl<T: Default + Clone + From<u8> + Shl<u64> + BitOrAssign<<T as Shl<u64>>::Output> + Shr<u64>> Bloom<T> {
    // num_items: determines the size of bloom filter. more items -> more bits needed -> bigger filter
    // false_positive_rate: lower rate = more bits = more memory. higher rate = fewer bits = less memory but more wrong answers.
    // max_bit: never allocate more than this, even if the math says you should.
    pub fn new(num_items: usize, false_positive_rate: f64, max_bits: usize) -> Self {
        
        // Derivation:
        //
        // given: m bits, k hash functions, n items to insert
        //
        // step 1: probability a specific bit is still 0 after all insertions
        //   one hash has a 1/m chance of hitting a specific bit
        //   so (1 - 1/m) chance of NOT hitting it
        //   with k hash functions per item and n items, total kn hashes
        //   probability bit is still 0: p0 = (1 - 1/m)^(kn)
        //   for large m, using the limit (1 - 1/m)^m ≈ e^(-1):
        //     p0 = ((1 - 1/m)^m)^(kn/m) ≈ (e^(-1))^(kn/m) = e^(-kn/m)
        //
        // step 2: false positive probability
        //   a false positive occurs when all k bits are set for an element NOT in the set
        //   each bit has probability (1 - p0) of being set
        //   all k bits set: p_fp = (1 - p0)^k = (1 - e^(-kn/m))^k
        //
        // step 3: find optimal k that minimizes p_fp
        //   take ln of both sides: ln(p_fp) = k * ln(1 - e^(-kn/m))
        //   substitute g = e^(-kn/m), so k = -(m/n) * ln(g)
        //   then ln(p_fp) = -(m/n) * ln(g) * ln(1 - g)
        //   minimize by differentiating w.r.t. g, set to 0:
        //     d/dg [ln(g) * ln(1-g)] = ln(1-g)/g - ln(g)/(1-g) = 0
        //   this gives g = 1/2, meaning e^(-kn/m) = 1/2
        //   solving: k = (m/n) * ln(2) ≈ 0.693 * (m/n)
        //
        // step 4: false positive rate at optimal k
        //   substituting g = 1/2 into p_fp = (1 - g)^k = (1/2)^k
        //   with k = (m/n) * ln(2):
        //     p_fp = (1/2)^((m/n) * ln(2)) = (2^(-ln(2)))^(m/n) ≈ (0.6185)^(m/n)
        //
        // step 5: solve for m given desired false positive rate p
        //   p = (0.6185)^(m/n)
        //   ln(p) = (m/n) * ln(0.6185)
        //   ln(0.6185) = -ln(2)^2 = -(ln2)^2
        //   therefore: m/n = -ln(p) / (ln2)^2
        //   so: m = -n * ln(p) / (ln2)^2
        //
        // step 6: solve for k given m
        //   k = (m/n) * ln(2)
        let num_bits = ((num_items as f64 * false_positive_rate.ln()) / (1f64 / 2f64.powf(2f64.ln())).ln()).ceil() as usize;
        let num_bits = num_bits.max(1).min(max_bits);
        
        let num_seeds = if num_items == 0 { 
            0 
        } else {
            ((num_bits as f64 / num_items as f64) * 2f64.ln()).round() as usize
        };
        let num_seeds = num_seeds.max(1);
        
        // generate random seeds for hash function
        let seeds: Vec<u64> = (0..num_seeds).map(|_| rand::random()).collect();
        
        Bloom {
            seed: seeds,
            bloom_filter: BitVec::new(num_bits as u64),
            counter: 0,
            _phantom: PhantomData,
        }
    }
    
    pub fn add(&mut self, item: &[u8]) where <T as Shr<u64>>::Output: BitAnd<T>, <<T as Shr<u64>>::Output as BitAnd<T>>::Output: PartialEq<T> {
        for &seed in &self.seed {
            // fnv (Fowler-Noll-Vo) is a fast, non-cryptographic hash function
            let mut hasher = FnvHasher::with_key(seed);
            hasher.write(item);
            
            let pos = hasher.finish() % self.bloom_filter.len();
            if !self.bloom_filter.get(pos) {
                self.bloom_filter.set(pos);
                self.counter += 1;
            }
        }
    }
    
    pub fn contains(&self, item: &[u8]) -> bool where <T as Shr<u64>>::Output: BitAnd<T>, <<T as Shr<u64>>::Output as BitAnd<T>>::Output: PartialEq<T> {
        for &seed in &self.seed {
            let mut hasher = FnvHasher::with_key(seed);
            hasher.write(item);
            let pos = hasher.finish() % self.bloom_filter.len();
            if !self.bloom_filter.get(pos) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_membership() {
        let mut bloom = Bloom::<u64>::new(1000, 0.01, 10000);
        bloom.add(b"hello");
        bloom.add(b"world");

        assert!(bloom.contains(b"hello"));
        assert!(bloom.contains(b"world"));
        assert!(!bloom.contains(b"foo"));
    }
}