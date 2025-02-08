use std::io::{Cursor, Read, Result};

pub struct BufferReader<'a> {
    cursor: Cursor<&'a [u8]>,
}

#[allow(dead_code)]
impl<'a> BufferReader<'a> {
    pub fn new(value: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(value),
        }
    }

    fn read_bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut buffer = [0u8; N];
        self.cursor.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        self.read_bytes::<1>().map(|v| v[0])
    }

    pub fn read_i8(&mut self) -> Result<i8> {
        self.read_u8().map(|v| v as i8)
    }

    pub fn read_le_u16(&mut self) -> Result<u16> {
        self.read_bytes().map(u16::from_le_bytes)
    }

    pub fn read_be_u16(&mut self) -> Result<u16> {
        self.read_bytes().map(u16::from_be_bytes)
    }

    pub fn read_le_i16(&mut self) -> Result<i16> {
        self.read_bytes().map(i16::from_le_bytes)
    }

    pub fn read_be_i16(&mut self) -> Result<i16> {
        self.read_bytes().map(i16::from_be_bytes)
    }

    pub fn read_le_u32(&mut self) -> Result<u32> {
        self.read_bytes().map(u32::from_le_bytes)
    }

    pub fn read_be_u32(&mut self) -> Result<u32> {
        self.read_bytes().map(u32::from_be_bytes)
    }

    pub fn read_le_i32(&mut self) -> Result<i32> {
        self.read_bytes().map(i32::from_le_bytes)
    }

    pub fn read_be_i32(&mut self) -> Result<i32> {
        self.read_bytes().map(i32::from_be_bytes)
    }

    pub fn read_le_u64(&mut self) -> Result<u64> {
        self.read_bytes().map(u64::from_le_bytes)
    }

    pub fn read_be_u64(&mut self) -> Result<u64> {
        self.read_bytes().map(u64::from_be_bytes)
    }

    pub fn read_le_i64(&mut self) -> Result<i64> {
        self.read_bytes().map(i64::from_le_bytes)
    }

    pub fn read_be_i64(&mut self) -> Result<i64> {
        self.read_bytes().map(i64::from_be_bytes)
    }

    pub fn read_le_f32(&mut self) -> Result<f32> {
        self.read_le_u32().map(f32::from_bits)
    }

    pub fn read_be_f32(&mut self) -> Result<f32> {
        self.read_be_u32().map(f32::from_bits)
    }

    pub fn read_le_f64(&mut self) -> Result<f64> {
        self.read_le_u64().map(f64::from_bits)
    }

    pub fn read_be_f64(&mut self) -> Result<f64> {
        self.read_be_u64().map(f64::from_bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u8() {
        let data = [0xAB];
        let mut reader = BufferReader::new(&data);
        assert_eq!(reader.read_u8().unwrap(), 0xAB);
    }

    #[test]
    fn test_read_i8() {
        let data = [0xFF]; // -1 in two's complement
        let mut reader = BufferReader::new(&data);
        assert_eq!(reader.read_i8().unwrap(), -1);
    }

    #[test]
    fn test_read_le_u16() {
        let data = [0x34, 0x12]; // 0x1234 in little-endian
        let mut reader = BufferReader::new(&data);
        assert_eq!(reader.read_le_u16().unwrap(), 0x1234);
    }

    #[test]
    fn test_read_be_u16() {
        let data = [0x12, 0x34]; // 0x1234 in big-endian
        let mut reader = BufferReader::new(&data);
        assert_eq!(reader.read_be_u16().unwrap(), 0x1234);
    }

    #[test]
    fn test_read_le_u32() {
        let data = [0x78, 0x56, 0x34, 0x12]; // 0x12345678 in little-endian
        let mut reader = BufferReader::new(&data);
        assert_eq!(reader.read_le_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_be_u32() {
        let data = [0x12, 0x34, 0x56, 0x78]; // 0x12345678 in big-endian
        let mut reader = BufferReader::new(&data);
        assert_eq!(reader.read_be_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_le_f32() {
        let data = [0x00, 0x00, 0x80, 0x3F]; // 1.0 in IEEE 754 little-endian
        let mut reader = BufferReader::new(&data);
        assert_eq!(reader.read_le_f32().unwrap(), 1.0);
    }

    #[test]
    fn test_read_be_f32() {
        let data = [0x3F, 0x80, 0x00, 0x00]; // 1.0 in IEEE 754 big-endian
        let mut reader = BufferReader::new(&data);
        assert_eq!(reader.read_be_f32().unwrap(), 1.0);
    }

    #[test]
    fn test_read_beyond_buffer() {
        let data = [0x01]; // Only 1 byte available
        let mut reader = BufferReader::new(&data);
        assert!(reader.read_le_u16().is_err()); // Not enough bytes to read a u16
    }
}