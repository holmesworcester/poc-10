//! Fixed-layout wire primitives.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    WrongLength { expected: usize, actual: usize },
    ValueTooLarge { max: usize, actual: usize },
    InvalidBool { actual: u8 },
    NonZeroPadding { index: usize },
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

pub type Tag<const N: usize> = FixedBytes<N>;
pub type Padding<const N: usize> = FixedBytes<N>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U8(pub u8);

impl FixedLayout for U8 {
    const LEN: usize = 1;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        expect_len(out, Self::LEN)?;
        out[0] = self.0;
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        expect_len(bytes, Self::LEN)?;
        Ok(Self(bytes[0]))
    }
}

impl From<u8> for U8 {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<U8> for u8 {
    fn from(value: U8) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U16be(pub u16);

impl FixedLayout for U16be {
    const LEN: usize = 2;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        expect_len(out, Self::LEN)?;
        out.copy_from_slice(&self.0.to_be_bytes());
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        expect_len(bytes, Self::LEN)?;
        let mut array = [0; Self::LEN];
        array.copy_from_slice(bytes);
        Ok(Self(u16::from_be_bytes(array)))
    }
}

impl From<u16> for U16be {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<U16be> for u16 {
    fn from(value: U16be) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U32be(pub u32);

impl FixedLayout for U32be {
    const LEN: usize = 4;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        expect_len(out, Self::LEN)?;
        out.copy_from_slice(&self.0.to_be_bytes());
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        expect_len(bytes, Self::LEN)?;
        let mut array = [0; Self::LEN];
        array.copy_from_slice(bytes);
        Ok(Self(u32::from_be_bytes(array)))
    }
}

impl From<u32> for U32be {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<U32be> for u32 {
    fn from(value: U32be) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U64be(pub u64);

impl FixedLayout for U64be {
    const LEN: usize = 8;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        expect_len(out, Self::LEN)?;
        out.copy_from_slice(&self.0.to_be_bytes());
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        expect_len(bytes, Self::LEN)?;
        let mut array = [0; Self::LEN];
        array.copy_from_slice(bytes);
        Ok(Self(u64::from_be_bytes(array)))
    }
}

impl From<u64> for U64be {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<U64be> for u64 {
    fn from(value: U64be) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bool8(pub bool);

impl FixedLayout for Bool8 {
    const LEN: usize = U8::LEN;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        U8(u8::from(self.0)).encode(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let value = U8::decode(bytes)?.0;
        match value {
            0 => Ok(Self(false)),
            1 => Ok(Self(true)),
            actual => Err(WireError::InvalidBool { actual }),
        }
    }
}

impl From<bool> for Bool8 {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl From<Bool8> for bool {
    fn from(value: Bool8) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FixedSlot<const N: usize> {
    len: usize,
    bytes: [u8; N],
}

impl<const N: usize> FixedSlot<N> {
    pub const DATA_LEN: usize = N;

    pub fn new(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > N {
            return Err(WireError::ValueTooLarge {
                max: N,
                actual: bytes.len(),
            });
        }

        let mut padded = [0; N];
        padded[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            len: bytes.len(),
            bytes: padded,
        })
    }

    pub fn from_padded(len: usize, bytes: [u8; N]) -> Result<Self, WireError> {
        if len > N {
            return Err(WireError::ValueTooLarge {
                max: N,
                actual: len,
            });
        }

        validate_zero_padding(&bytes, len)?;
        Ok(Self { len, bytes })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn padded_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> TryFrom<&[u8]> for FixedSlot<N> {
    type Error = WireError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

impl<const N: usize> AsRef<[u8]> for FixedSlot<N> {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

impl<const N: usize> FixedLayout for FixedSlot<N> {
    const LEN: usize = U32be::LEN + N;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        expect_len(out, Self::LEN)?;
        let len = u32::try_from(self.len).map_err(|_| WireError::ValueTooLarge {
            max: u32::MAX as usize,
            actual: self.len,
        })?;
        U32be(len).encode(&mut out[..U32be::LEN])?;
        out[U32be::LEN..].fill(0);
        out[U32be::LEN..U32be::LEN + self.len].copy_from_slice(self.bytes());
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        expect_len(bytes, Self::LEN)?;
        let len = U32be::decode(&bytes[..U32be::LEN])?.0 as usize;
        if len > N {
            return Err(WireError::ValueTooLarge {
                max: N,
                actual: len,
            });
        }

        let mut padded = [0; N];
        padded.copy_from_slice(&bytes[U32be::LEN..]);
        validate_zero_padding(&padded, len)?;
        Ok(Self { len, bytes: padded })
    }
}

pub const fn fixed_tag<const N: usize>(bytes: &[u8; N]) -> Tag<N> {
    FixedBytes(*bytes)
}

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

fn validate_zero_padding(bytes: &[u8], len: usize) -> Result<(), WireError> {
    if let Some(offset) = bytes[len..].iter().position(|byte| *byte != 0) {
        Err(WireError::NonZeroPadding {
            index: len + offset,
        })
    } else {
        Ok(())
    }
}

pub fn put_u8(value: u8, out: &mut [u8]) -> Result<(), WireError> {
    U8(value).encode(out)
}

pub fn take_u8(bytes: &[u8]) -> Result<u8, WireError> {
    Ok(U8::decode(bytes)?.0)
}

pub fn put_u16be(value: u16, out: &mut [u8]) -> Result<(), WireError> {
    U16be(value).encode(out)
}

pub fn take_u16be(bytes: &[u8]) -> Result<u16, WireError> {
    Ok(U16be::decode(bytes)?.0)
}

pub fn put_u32be(value: u32, out: &mut [u8]) -> Result<(), WireError> {
    U32be(value).encode(out)
}

pub fn take_u32be(bytes: &[u8]) -> Result<u32, WireError> {
    Ok(U32be::decode(bytes)?.0)
}

pub fn put_u64be(value: u64, out: &mut [u8]) -> Result<(), WireError> {
    U64be(value).encode(out)
}

pub fn take_u64be(bytes: &[u8]) -> Result<u64, WireError> {
    Ok(U64be::decode(bytes)?.0)
}

pub fn put_bool8(value: bool, out: &mut [u8]) -> Result<(), WireError> {
    Bool8(value).encode(out)
}

pub fn take_bool8(bytes: &[u8]) -> Result<bool, WireError> {
    Ok(Bool8::decode(bytes)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_bytes_reject_wrong_lengths() {
        assert_eq!(
            FixedBytes::<32>::decode(&[0; 31]).unwrap_err(),
            WireError::WrongLength {
                expected: 32,
                actual: 31
            }
        );
        assert_eq!(
            FixedBytes::<32>::decode(&[0; 33]).unwrap_err(),
            WireError::WrongLength {
                expected: 32,
                actual: 33
            }
        );
        assert!(FixedBytes::<32>::decode(&[0; 32]).is_ok());
    }

    #[test]
    fn fixed_layout_types_reject_wrong_lengths() {
        assert!(U8::decode(&[]).is_err());
        assert!(U16be::decode(&[0]).is_err());
        assert!(U32be::decode(&[0; 3]).is_err());
        assert!(U64be::decode(&[0; 7]).is_err());
        assert!(Bool8::decode(&[0, 0]).is_err());

        let slot = FixedSlot::<3>::new(b"abc").unwrap();
        let mut short = [0; FixedSlot::<3>::LEN - 1];
        assert!(slot.encode(&mut short).is_err());
        assert!(FixedSlot::<3>::decode(&[0; FixedSlot::<3>::LEN + 1]).is_err());
    }

    #[test]
    fn big_endian_values_round_trip() {
        let cases = [
            (U16be::LEN, 0x1234_u64),
            (U32be::LEN, 0x1234_5678_u64),
            (U64be::LEN, 0x1234_5678_9abc_def0_u64),
        ];

        let mut out = [0; U64be::LEN];

        U16be(cases[0].1 as u16)
            .encode(&mut out[..cases[0].0])
            .unwrap();
        assert_eq!(&out[..cases[0].0], &[0x12, 0x34]);
        assert_eq!(U16be::decode(&out[..cases[0].0]).unwrap().0, 0x1234);

        U32be(cases[1].1 as u32)
            .encode(&mut out[..cases[1].0])
            .unwrap();
        assert_eq!(&out[..cases[1].0], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(U32be::decode(&out[..cases[1].0]).unwrap().0, 0x1234_5678);

        U64be(cases[2].1).encode(&mut out[..cases[2].0]).unwrap();
        assert_eq!(
            &out[..cases[2].0],
            &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]
        );
        assert_eq!(
            U64be::decode(&out[..cases[2].0]).unwrap().0,
            0x1234_5678_9abc_def0
        );

        put_u64be(42, &mut out).unwrap();
        assert_eq!(take_u64be(&out).unwrap(), 42);
    }

    #[test]
    fn u8_and_bool8_round_trip() {
        let mut out = [0; U8::LEN];

        put_u8(7, &mut out).unwrap();
        assert_eq!(take_u8(&out).unwrap(), 7);

        put_bool8(true, &mut out).unwrap();
        assert_eq!(out, [1]);
        assert!(take_bool8(&out).unwrap());

        put_bool8(false, &mut out).unwrap();
        assert_eq!(out, [0]);
        assert!(!take_bool8(&out).unwrap());

        assert_eq!(
            Bool8::decode(&[2]).unwrap_err(),
            WireError::InvalidBool { actual: 2 }
        );
    }

    #[test]
    fn fixed_slot_round_trips_with_zero_padding() {
        let slot = FixedSlot::<5>::new(b"abc").unwrap();
        let mut out = [0xff; FixedSlot::<5>::LEN];

        slot.encode(&mut out).unwrap();
        assert_eq!(&out, &[0, 0, 0, 3, b'a', b'b', b'c', 0, 0]);

        let decoded = FixedSlot::<5>::decode(&out).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded.bytes(), b"abc");
        assert_eq!(decoded.padded_bytes(), &[b'a', b'b', b'c', 0, 0]);
    }

    #[test]
    fn fixed_slot_rejects_overflow_and_non_zero_padding() {
        assert_eq!(
            FixedSlot::<2>::new(b"abc").unwrap_err(),
            WireError::ValueTooLarge { max: 2, actual: 3 }
        );

        let mut out = [0; FixedSlot::<4>::LEN];
        U32be(2).encode(&mut out[..U32be::LEN]).unwrap();
        out[U32be::LEN..].copy_from_slice(&[b'a', b'b', 0, 1]);
        assert_eq!(
            FixedSlot::<4>::decode(&out).unwrap_err(),
            WireError::NonZeroPadding { index: 3 }
        );

        U32be(5).encode(&mut out[..U32be::LEN]).unwrap();
        assert_eq!(
            FixedSlot::<4>::decode(&out).unwrap_err(),
            WireError::ValueTooLarge { max: 4, actual: 5 }
        );
    }

    #[test]
    fn fixed_tag_wraps_fixed_bytes() {
        const TAG: Tag<3> = fixed_tag(b"abc");

        let mut out = [0; Tag::<3>::LEN];
        TAG.encode(&mut out).unwrap();
        assert_eq!(out, *b"abc");
    }
}
