use std::io::{Write, Result};

pub trait BinaryWriter {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()>;

    fn write_u8(&mut self, value: u8) -> Result<()> {
        self.write_bytes(&[value])
    }

    fn write_i8(&mut self, value: i8) -> Result<()> {
        self.write_u8(value as u8)
    }

    fn write_le_u16(&mut self, value: u16) -> Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_be_u16(&mut self, value: u16) -> Result<()> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_le_i16(&mut self, value: i16) -> Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_be_i16(&mut self, value: i16) -> Result<()> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_le_u32(&mut self, value: u32) -> Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_be_u32(&mut self, value: u32) -> Result<()> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_le_i32(&mut self, value: i32) -> Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_be_i32(&mut self, value: i32) -> Result<()> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_le_u64(&mut self, value: u64) -> Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_be_u64(&mut self, value: u64) -> Result<()> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_le_i64(&mut self, value: i64) -> Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_be_i64(&mut self, value: i64) -> Result<()> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_le_f32(&mut self, value: f32) -> Result<()> {
        self.write_le_u32(value.to_bits())
    }

    fn write_be_f32(&mut self, value: f32) -> Result<()> {
        self.write_be_u32(value.to_bits())
    }

    fn write_le_f64(&mut self, value: f64) -> Result<()> {
        self.write_le_u64(value.to_bits())
    }

    fn write_be_f64(&mut self, value: f64) -> Result<()> {
        self.write_be_u64(value.to_bits())
    }
}

impl<T> BinaryWriter for T where T: Write {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_all(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_u8() {
        let mut buffer = vec![];
        buffer.write_u8(0xAB).unwrap();
        assert_eq!(buffer, [0xAB]);
    }

    #[test]
    fn test_write_le_u16() {
        let mut buffer = vec![];
        buffer.write_le_u16(0x1234).unwrap();
        assert_eq!(buffer, [0x34, 0x12]);
    }

    #[test]
    fn test_write_be_u16() {
        let mut buffer = vec![];
        buffer.write_be_u16(0x1234).unwrap();
        assert_eq!(buffer, [0x12, 0x34]);
    }

    #[test]
    fn test_write_le_u32() {
        let mut buffer = vec![];
        buffer.write_le_u32(0x12345678).unwrap();
        assert_eq!(buffer, [0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_write_be_u32() {
        let mut buffer = vec![];
        buffer.write_be_u32(0x12345678).unwrap();
        assert_eq!(buffer, [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_write_le_f32() {
        let mut buffer = vec![];
        buffer.write_le_f32(1.0).unwrap();
        assert_eq!(buffer, [0x00, 0x00, 0x80, 0x3F]);
    }

    #[test]
    fn test_write_be_f32() {
        let mut buffer = vec![];
        buffer.write_be_f32(1.0).unwrap();
        assert_eq!(buffer, [0x3F, 0x80, 0x00, 0x00]);
    }
}
