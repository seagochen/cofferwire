use crate::DecodeError;

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) const fn new(bytes: &'a [u8], offset: usize) -> Self {
        Self { bytes, offset }
    }

    pub(crate) const fn offset(&self) -> usize {
        self.offset
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let value = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or(DecodeError::Truncated {
                offset: self.offset,
            })?;
        self.offset += 1;
        Ok(value)
    }

    fn argument(&mut self, expected_major: u8, expected: &'static str) -> Result<u64, DecodeError> {
        let start = self.offset;
        let initial = self.byte()?;
        if initial >> 5 != expected_major {
            return Err(DecodeError::UnexpectedType {
                offset: start,
                expected,
            });
        }
        let additional = initial & 0x1f;
        let (value, minimum) = match additional {
            value @ 0..=23 => return Ok(u64::from(value)),
            24 => (u64::from(self.byte()?), 24),
            25 => (
                u64::from(u16::from_be_bytes([self.byte()?, self.byte()?])),
                256,
            ),
            26 => (
                u64::from(u32::from_be_bytes([
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                ])),
                65_536,
            ),
            27 => (
                u64::from_be_bytes([
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                ]),
                4_294_967_296,
            ),
            _ => {
                return Err(DecodeError::UnexpectedType {
                    offset: start,
                    expected,
                })
            }
        };
        if value < minimum {
            return Err(DecodeError::NonCanonicalArgument { offset: start });
        }
        Ok(value)
    }

    pub(crate) fn unsigned(&mut self, field: &'static str) -> Result<u64, DecodeError> {
        self.argument(0, field)
    }

    pub(crate) fn array(&mut self, field: &'static str, expected: u64) -> Result<(), DecodeError> {
        let actual = self.array_length()?;
        if actual != expected {
            return Err(DecodeError::WrongArrayLength {
                field,
                expected,
                actual,
            });
        }
        Ok(())
    }

    pub(crate) fn array_length(&mut self) -> Result<u64, DecodeError> {
        self.argument(4, "definite-length array")
    }

    pub(crate) fn bytes(
        &mut self,
        field: &'static str,
        max: usize,
    ) -> Result<&'a [u8], DecodeError> {
        let length = self.argument(2, "definite-length byte string")?;
        if length > max as u64 {
            return Err(DecodeError::ByteStringTooLarge {
                field,
                max,
                actual: length,
            });
        }
        let length = usize::try_from(length).map_err(|_| DecodeError::ByteStringTooLarge {
            field,
            max,
            actual: length,
        })?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DecodeError::ByteStringTooLarge {
                field,
                max,
                actual: length as u64,
            })?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DecodeError::Truncated {
                offset: self.offset,
            })?;
        self.offset = end;
        Ok(value)
    }
}

pub(crate) fn encode_argument(output: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | u8::try_from(value).expect("direct argument")),
        24..=0xff => {
            output.push(prefix | 24);
            output.push(u8::try_from(value).expect("one-byte argument"));
        }
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend(
                u16::try_from(value)
                    .expect("two-byte argument")
                    .to_be_bytes(),
            );
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend(
                u32::try_from(value)
                    .expect("four-byte argument")
                    .to_be_bytes(),
            );
        }
        _ => {
            output.push(prefix | 27);
            output.extend(value.to_be_bytes());
        }
    }
}

pub(crate) fn encode_unsigned(output: &mut Vec<u8>, value: u64) {
    encode_argument(output, 0, value);
}

pub(crate) fn encode_array(output: &mut Vec<u8>, length: u64) {
    encode_argument(output, 4, length);
}

pub(crate) fn encode_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    encode_argument(
        output,
        2,
        u64::try_from(bytes.len()).expect("bounded frame length fits u64"),
    );
    output.extend_from_slice(bytes);
}
