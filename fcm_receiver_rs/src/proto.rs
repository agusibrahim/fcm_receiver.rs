use crate::error::{ProtoError, ProtoErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireType {
    Varint = 0,
    Bit64 = 1,
    LengthDelimited = 2,
    StartGroup = 3,
    EndGroup = 4,
    Bit32 = 5,
}

impl WireType {
    pub fn from_u8(value: u8) -> std::result::Result<Self, ProtoError> {
        match value {
            0 => Ok(WireType::Varint),
            1 => Ok(WireType::Bit64),
            2 => Ok(WireType::LengthDelimited),
            3 => Ok(WireType::StartGroup),
            4 => Ok(WireType::EndGroup),
            5 => Ok(WireType::Bit32),
            other => Err(ProtoError::with_context(
                ProtoErrorKind::UnsupportedWireType(other),
                "wire type",
            )),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ProtoEncoder {
    buf: Vec<u8>,
}

impl ProtoEncoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn clear(&mut self) {
        self.buf.clear();
    }

    pub fn encode_field_number(&mut self, field_number: u32, wire_type: WireType) {
        let key = ((field_number as u64) << 3) | (wire_type as u64);
        self.encode_varint_internal(key);
    }

    pub fn encode_varint_value(&mut self, value: u64) {
        self.encode_varint_internal(value);
    }

    pub fn encode_bool(&mut self, field_number: u32, value: bool) {
        self.encode_field_number(field_number, WireType::Varint);
        self.encode_varint_internal(value as u64);
    }

    pub fn encode_int32(&mut self, field_number: u32, value: i32) {
        self.encode_field_number(field_number, WireType::Varint);
        self.encode_varint_internal(value as u64);
    }

    pub fn encode_uint32(&mut self, field_number: u32, value: u32) {
        self.encode_field_number(field_number, WireType::Varint);
        self.encode_varint_internal(value as u64);
    }

    pub fn encode_int64(&mut self, field_number: u32, value: i64) {
        self.encode_field_number(field_number, WireType::Varint);
        self.encode_varint_internal(value as u64);
    }

    pub fn encode_uint64(&mut self, field_number: u32, value: u64) {
        self.encode_field_number(field_number, WireType::Varint);
        self.encode_varint_internal(value);
    }

    pub fn encode_zigzag(&mut self, value: i64) {
        let encoded = ((value << 1) ^ (value >> 63)) as u64;
        self.encode_varint_internal(encoded);
    }

    pub fn encode_string(&mut self, field_number: u32, value: &str) {
        self.encode_field_number(field_number, WireType::LengthDelimited);
        self.encode_varint_internal(value.len() as u64);
        self.buf.extend_from_slice(value.as_bytes());
    }

    pub fn encode_bytes(&mut self, field_number: u32, value: &[u8]) {
        self.encode_field_number(field_number, WireType::LengthDelimited);
        self.encode_varint_internal(value.len() as u64);
        self.buf.extend_from_slice(value);
    }

    pub fn encode_fixed64(&mut self, field_number: u32, value: u64) {
        self.encode_field_number(field_number, WireType::Bit64);
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn encode_fixed32(&mut self, field_number: u32, value: u32) {
        self.encode_field_number(field_number, WireType::Bit32);
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn encode_float(&mut self, field_number: u32, value: f32) {
        self.encode_fixed32(field_number, value.to_bits());
    }

    pub fn encode_double(&mut self, field_number: u32, value: f64) {
        self.encode_fixed64(field_number, value.to_bits());
    }

    fn encode_varint_internal(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.buf.push(((value as u8) & 0x7F) | 0x80);
            value >>= 7;
        }
        self.buf.push(value as u8);
    }
}

#[derive(Debug, Clone)]
pub struct ProtoDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ProtoDecoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn reset(&mut self, buf: &'a [u8]) {
        self.buf = buf;
        self.pos = 0;
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn decode_field_number(&mut self) -> std::result::Result<(u32, WireType), ProtoError> {
        let (key, n) = self.decode_varint_raw()?;
        let field_number = (key >> 3) as u32;
        let wire_type = WireType::from_u8((key & 0x7) as u8)?;
        self.pos += n;
        Ok((field_number, wire_type))
    }

    pub fn decode_varint(&mut self) -> std::result::Result<u64, ProtoError> {
        let (value, n) = self.decode_varint_raw()?;
        self.pos += n;
        Ok(value)
    }

    pub fn decode_int32(&mut self) -> std::result::Result<i32, ProtoError> {
        Ok(self.decode_varint()? as i32)
    }

    pub fn decode_uint32(&mut self) -> std::result::Result<u32, ProtoError> {
        Ok(self.decode_varint()? as u32)
    }

    pub fn decode_int64(&mut self) -> std::result::Result<i64, ProtoError> {
        Ok(self.decode_varint()? as i64)
    }

    pub fn decode_uint64(&mut self) -> std::result::Result<u64, ProtoError> {
        self.decode_varint()
    }

    pub fn decode_bool(&mut self) -> std::result::Result<bool, ProtoError> {
        Ok(self.decode_varint()? != 0)
    }

    pub fn decode_string(&mut self) -> std::result::Result<String, ProtoError> {
        let len = self.decode_length()?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| ProtoError::new(ProtoErrorKind::InvalidLength))?;
        if end > self.buf.len() {
            return Err(ProtoError::new(ProtoErrorKind::InvalidLength));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        String::from_utf8(slice.to_vec())
            .map_err(|_| ProtoError::with_context(ProtoErrorKind::InvalidLength, "string utf8"))
    }

    pub fn decode_bytes(&mut self) -> std::result::Result<&'a [u8], ProtoError> {
        let len = self.decode_length()?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| ProtoError::new(ProtoErrorKind::InvalidLength))?;
        if end > self.buf.len() {
            return Err(ProtoError::new(ProtoErrorKind::InvalidLength));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn decode_fixed64(&mut self) -> std::result::Result<u64, ProtoError> {
        let end = self
            .pos
            .checked_add(8)
            .ok_or_else(|| ProtoError::new(ProtoErrorKind::InvalidLength))?;
        if end > self.buf.len() {
            return Err(ProtoError::new(ProtoErrorKind::Eof));
        }
        let value = u64::from_le_bytes(self.buf[self.pos..end].try_into().unwrap());
        self.pos = end;
        Ok(value)
    }

    pub fn decode_fixed32(&mut self) -> std::result::Result<u32, ProtoError> {
        let end = self
            .pos
            .checked_add(4)
            .ok_or_else(|| ProtoError::new(ProtoErrorKind::InvalidLength))?;
        if end > self.buf.len() {
            return Err(ProtoError::new(ProtoErrorKind::Eof));
        }
        let value = u32::from_le_bytes(self.buf[self.pos..end].try_into().unwrap());
        self.pos = end;
        Ok(value)
    }

    pub fn skip_field(&mut self, wire_type: WireType) -> std::result::Result<(), ProtoError> {
        match wire_type {
            WireType::Varint => {
                let (_, n) = self.decode_varint_raw()?;
                self.pos += n;
                Ok(())
            }
            WireType::Bit64 => self.advance(8),
            WireType::LengthDelimited => {
                let len = self.decode_length()?;
                self.advance(len)
            }
            WireType::StartGroup => self.skip_group(),
            WireType::EndGroup => Ok(()),
            WireType::Bit32 => self.advance(4),
        }
    }

    fn skip_group(&mut self) -> std::result::Result<(), ProtoError> {
        let mut depth = 1;
        while depth > 0 {
            let (key, n) = self.decode_varint_raw()?;
            self.pos += n;
            let wire_type = WireType::from_u8((key & 0x7) as u8)?;
            match wire_type {
                WireType::StartGroup => depth += 1,
                WireType::EndGroup => depth -= 1,
                other => self.skip_field(other)?,
            }
        }
        Ok(())
    }

    fn advance(&mut self, len: usize) -> std::result::Result<(), ProtoError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| ProtoError::new(ProtoErrorKind::InvalidLength))?;
        if end > self.buf.len() {
            return Err(ProtoError::new(ProtoErrorKind::Eof));
        }
        self.pos = end;
        Ok(())
    }

    fn decode_length(&mut self) -> std::result::Result<usize, ProtoError> {
        let (len, n) = self.decode_varint_raw()?;
        self.pos += n;
        len.try_into()
            .map_err(|_| ProtoError::new(ProtoErrorKind::InvalidLength))
    }

    fn decode_varint_raw(&self) -> std::result::Result<(u64, usize), ProtoError> {
        let mut x = 0u64;
        let mut s = 0u32;
        for (i, &b) in self.buf[self.pos..].iter().enumerate() {
            if b < 0x80 {
                if i == 9 && b > 1 {
                    return Err(ProtoError::new(ProtoErrorKind::InvalidVarint));
                }
                x |= ((b & 0x7F) as u64) << s;
                return Ok((x, i + 1));
            }
            x |= ((b & 0x7F) as u64) << s;
            s += 7;
            if s >= 64 {
                return Err(ProtoError::new(ProtoErrorKind::InvalidVarint));
            }
        }
        Err(ProtoError::new(ProtoErrorKind::Eof))
    }
}

pub fn put_uvarint(mut x: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    while x >= 0x80 {
        buf.push(((x as u8) & 0x7F) | 0x80);
        x >>= 7;
    }
    buf.push(x as u8);
    buf
}
