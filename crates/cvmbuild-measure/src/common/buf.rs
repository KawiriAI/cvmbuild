//! Fixed-size, zero-initialized buffer with typed little-endian field accessors.

pub struct StructBuffer {
    buf: Vec<u8>,
}

impl StructBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            buf: vec![0u8; size],
        }
    }

    pub fn set_u8(&mut self, offset: usize, value: u8) {
        self.buf[offset] = value;
    }

    pub fn set_u16(&mut self, offset: usize, value: u16) {
        self.buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    pub fn set_u32(&mut self, offset: usize, value: u32) {
        self.buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub fn set_u64(&mut self, offset: usize, value: u64) {
        self.buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    pub fn set_bytes(&mut self, offset: usize, data: &[u8]) {
        self.buf[offset..offset + data.len()].copy_from_slice(data);
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_read_u64_le() {
        let mut buf = StructBuffer::new(16);
        buf.set_u64(0, 0x0102030405060708);
        assert_eq!(buf.as_bytes()[0], 0x08);
        assert_eq!(buf.as_bytes()[7], 0x01);
    }

    #[test]
    fn set_bytes_copies_data() {
        let mut buf = StructBuffer::new(8);
        buf.set_bytes(2, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(buf.as_bytes()[2], 0xAA);
        assert_eq!(buf.as_bytes()[4], 0xCC);
    }
}
