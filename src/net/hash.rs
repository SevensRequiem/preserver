//! SHA-256 and SHA-512 whose state can be saved and restored on a block boundary.
//!
//! sha2 0.10 keeps its buffer private, so the state is driven through `compress256/512`
//! directly: a checkpoint taken where the buffer is empty is exactly the eight chaining words
//! plus the byte count, which is what the `.part.json` sidecar stores.

use sha2::digest::generic_array::GenericArray;

pub(crate) trait Algo {
    type Word: Copy;
    const BLOCK: usize;
    /// Width of the trailing big-endian bit-length field in the padding.
    const LEN: usize;
    const INIT: [Self::Word; 8];
    fn compress(state: &mut [Self::Word; 8], block: &[u8]);
    fn digest(state: &[Self::Word; 8]) -> Vec<u8>;
}

pub(crate) struct S256;
pub(crate) struct S512;

impl Algo for S256 {
    type Word = u32;
    const BLOCK: usize = 64;
    const LEN: usize = 8;
    const INIT: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    fn compress(state: &mut [u32; 8], block: &[u8]) {
        sha2::compress256(state, std::slice::from_ref(GenericArray::from_slice(block)));
    }

    fn digest(state: &[u32; 8]) -> Vec<u8> {
        state.iter().flat_map(|w| w.to_be_bytes()).collect()
    }
}

impl Algo for S512 {
    type Word = u64;
    const BLOCK: usize = 128;
    const LEN: usize = 16;
    const INIT: [u64; 8] = [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b,
        0x5be0_cd19_137e_2179,
    ];

    fn compress(state: &mut [u64; 8], block: &[u8]) {
        sha2::compress512(state, std::slice::from_ref(GenericArray::from_slice(block)));
    }

    fn digest(state: &[u64; 8]) -> Vec<u8> {
        state.iter().flat_map(|w| w.to_be_bytes()).collect()
    }
}

pub(crate) struct Resumable<A: Algo> {
    state: [A::Word; 8],
    /// Bytes fed so far, buffered ones included.
    len: u64,
    buf: [u8; 128],
}

impl<A: Algo> Resumable<A> {
    pub(crate) fn new() -> Self {
        Self::resume(A::INIT, 0)
    }

    /// Restores a state saved by `midstate`.
    pub(crate) fn resume(state: [A::Word; 8], len: u64) -> Self {
        debug_assert_eq!(len % A::BLOCK as u64, 0);
        Self {
            state,
            len,
            buf: [0; 128],
        }
    }

    fn fill(&self) -> usize {
        // The remainder is below BLOCK (at most 128), so it fits.
        usize::try_from(self.len % A::BLOCK as u64).unwrap_or_default()
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        let fill = self.fill();
        self.len += data.len() as u64;
        if fill > 0 {
            let take = (A::BLOCK - fill).min(data.len());
            self.buf[fill..fill + take].copy_from_slice(&data[..take]);
            data = &data[take..];
            if fill + take < A::BLOCK {
                return;
            }
            A::compress(&mut self.state, &self.buf[..A::BLOCK]);
        }
        let mut blocks = data.chunks_exact(A::BLOCK);
        for b in &mut blocks {
            A::compress(&mut self.state, b);
        }
        let rest = blocks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
    }

    /// The chaining words and length, or `None` when part of a block is still buffered.
    pub(crate) fn midstate(&self) -> Option<([A::Word; 8], u64)> {
        (self.fill() == 0).then_some((self.state, self.len))
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        let bits = u128::from(self.len) * 8;
        let fill = self.fill();
        let mut tail = [0u8; 256];
        tail[..fill].copy_from_slice(&self.buf[..fill]);
        tail[fill] = 0x80;
        let total = if fill + 1 + A::LEN <= A::BLOCK {
            A::BLOCK
        } else {
            2 * A::BLOCK
        };
        tail[total - A::LEN..total].copy_from_slice(&bits.to_be_bytes()[16 - A::LEN..]);
        for b in tail[..total].chunks_exact(A::BLOCK) {
            A::compress(&mut self.state, b);
        }
        A::digest(&self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn data(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| u8::try_from((i * 31 + i / 7) % 251).unwrap())
            .collect()
    }

    #[test]
    fn matches_sha2_for_every_padding_case_and_split() {
        for n in (0..300).chain([1000, 4095, 4096, 4097, 65_536]) {
            let d = data(n);
            let want256 = sha2::Sha256::digest(&d).to_vec();
            let want512 = sha2::Sha512::digest(&d).to_vec();
            for split in [0, 1, 63, 64, 65, 127, 128, 129, n / 2, n] {
                let split = split.min(n);
                let mut a = Resumable::<S256>::new();
                let mut b = Resumable::<S512>::new();
                a.update(&d[..split]);
                b.update(&d[..split]);
                a.update(&d[split..]);
                b.update(&d[split..]);
                assert_eq!(a.finish(), want256, "sha256 n={n} split={split}");
                assert_eq!(b.finish(), want512, "sha512 n={n} split={split}");
            }
        }
    }

    #[test]
    fn midstate_round_trips_on_block_boundaries_only() {
        let d = data(10_000);
        let mut a = Resumable::<S256>::new();
        let mut b = Resumable::<S512>::new();
        a.update(&d[..100]);
        assert!(a.midstate().is_none(), "100 is not a multiple of 64");
        a.update(&d[100..1024]);
        b.update(&d[..1024]);
        let (sa, la) = a.midstate().unwrap();
        let (sb, lb) = b.midstate().unwrap();
        assert_eq!((la, lb), (1024, 1024));
        let mut a = Resumable::<S256>::resume(sa, la);
        let mut b = Resumable::<S512>::resume(sb, lb);
        a.update(&d[1024..]);
        b.update(&d[1024..]);
        assert_eq!(a.finish(), sha2::Sha256::digest(&d).to_vec());
        assert_eq!(b.finish(), sha2::Sha512::digest(&d).to_vec());
    }
}
