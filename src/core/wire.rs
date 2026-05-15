//! Fixed-layout wire primitives.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    WrongLength { expected: usize, actual: usize },
}

pub trait FixedLayout: Sized {
    const LEN: usize;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError>;
    fn decode(bytes: &[u8]) -> Result<Self, WireError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> FixedLayout for FixedBytes<N> {
    const LEN: usize = N;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        expect_len(out, N)?;
        out.copy_from_slice(&self.0);
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        expect_len(bytes, N)?;
        let mut out = [0; N];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }
}

pub type Id32 = FixedBytes<32>;
pub type Hash32 = FixedBytes<32>;
pub type PublicKey32 = FixedBytes<32>;
pub type Signature64 = FixedBytes<64>;
pub type Nonce24 = FixedBytes<24>;
pub type Tag<const N: usize> = FixedBytes<N>;
pub type Padding<const N: usize> = FixedBytes<N>;
pub type Ciphertext<const N: usize> = FixedBytes<N>;

pub fn expect_len(bytes: &[u8], expected: usize) -> Result<(), WireError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(WireError::WrongLength {
            expected,
            actual: bytes.len(),
        })
    }
}

pub fn put_u64be(value: u64, out: &mut [u8]) -> Result<(), WireError> {
    expect_len(out, 8)?;
    out.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

pub fn take_u64be(bytes: &[u8]) -> Result<u64, WireError> {
    expect_len(bytes, 8)?;
    let mut array = [0; 8];
    array.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(array))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_bytes_reject_wrong_lengths() {
        assert!(Id32::decode(&[0; 31]).is_err());
        assert!(Id32::decode(&[0; 33]).is_err());
        assert!(Id32::decode(&[0; 32]).is_ok());
    }

    #[test]
    fn u64be_round_trips_and_rejects_wrong_lengths() {
        let mut out = [0; 8];
        put_u64be(42, &mut out).unwrap();
        assert_eq!(take_u64be(&out).unwrap(), 42);
        assert!(take_u64be(&out[..7]).is_err());
    }
}
