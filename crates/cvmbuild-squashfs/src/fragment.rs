/// Fragment table: packs file tails (< 128 KiB) into shared blocks.
///
/// Files smaller than one data block, or the remainder of a file that
/// doesn't fill a final block, are packed into fragment blocks. The
/// fragment table records where each compressed fragment block lives.
use std::io::{self, Seek, Write};

use crate::format::{
    FragmentEntry, DATA_BLOCK_SIZE, DATA_BLOCK_UNCOMPRESSED, METADATA_BLOCK_SIZE,
    META_BLOCK_UNCOMPRESSED,
};

const ZSTD_LEVEL: i32 = 3;

pub struct FragmentTable {
    /// Current fragment block accumulator.
    buf: Vec<u8>,
    /// Completed fragment entries (one per flushed block).
    entries: Vec<FragmentEntry>,
}

impl FragmentTable {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            entries: Vec::new(),
        }
    }

    /// Number of fragment entries (= number of fragment blocks).
    pub fn count(&self) -> u32 {
        self.entries.len() as u32
    }

    /// Add a file tail to the current fragment block.
    ///
    /// Returns `(fragment_index, offset_within_fragment_block)`.
    /// If the buffer fills up, it is flushed to `output`.
    pub fn add_fragment<W: Write + Seek>(
        &mut self,
        data: &[u8],
        output: &mut W,
    ) -> io::Result<(u32, u32)> {
        assert!(
            data.len() <= DATA_BLOCK_SIZE as usize,
            "fragment data must be <= block size"
        );

        // If adding this data would exceed block size, flush first
        if !self.buf.is_empty() && self.buf.len() + data.len() > DATA_BLOCK_SIZE as usize {
            self.flush_block(output)?;
        }

        let offset = self.buf.len() as u32;
        let frag_idx = self.entries.len() as u32; // index of current (possibly not yet flushed) block
        self.buf.extend_from_slice(data);

        Ok((frag_idx, offset))
    }

    fn flush_block<W: Write + Seek>(&mut self, output: &mut W) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }

        let raw = std::mem::take(&mut self.buf);
        let start = output.stream_position()?;

        let compressed = zstd::bulk::compress(&raw, ZSTD_LEVEL).ok();
        let (stored, is_compressed) = match compressed {
            Some(ref c) if c.len() < raw.len() => (c.as_slice(), true),
            _ => (raw.as_slice(), false),
        };

        output.write_all(stored)?;

        let size = if is_compressed {
            stored.len() as u32
        } else {
            stored.len() as u32 | DATA_BLOCK_UNCOMPRESSED
        };

        self.entries.push(FragmentEntry {
            start,
            size,
            unused: 0,
        });

        self.buf = Vec::new();
        Ok(())
    }

    /// Flush any remaining partial fragment block.
    pub fn finish<W: Write + Seek>(&mut self, output: &mut W) -> io::Result<()> {
        self.flush_block(output)
    }

    /// Write the fragment entry lookup table.
    ///
    /// The fragment table is a two-level structure:
    /// 1. Fragment entries are written as metadata blocks (8 KiB each)
    /// 2. A lookup table of u64 offsets points to each metadata block
    ///
    /// Returns the byte offset of the lookup table (for the superblock).
    pub fn write_table<W: Write + Seek>(&self, output: &mut W) -> io::Result<u64> {
        if self.entries.is_empty() {
            return output.stream_position();
        }

        // Serialize all fragment entries into a byte buffer
        let mut entry_bytes = Vec::with_capacity(self.entries.len() * FragmentEntry::SIZE);
        for entry in &self.entries {
            entry.write_to(&mut entry_bytes)?;
        }

        // Write as metadata blocks, recording the offset of each block
        let mut block_offsets: Vec<u64> = Vec::new();
        let mut pos = 0;

        while pos < entry_bytes.len() {
            let end = (pos + METADATA_BLOCK_SIZE).min(entry_bytes.len());
            let chunk = &entry_bytes[pos..end];

            let block_start = output.stream_position()?;
            block_offsets.push(block_start);

            let compressed = zstd::bulk::compress(chunk, ZSTD_LEVEL).ok();
            match compressed {
                Some(ref c) if c.len() < chunk.len() => {
                    let header = c.len() as u16;
                    output.write_all(&header.to_le_bytes())?;
                    output.write_all(c)?;
                }
                _ => {
                    let header = chunk.len() as u16 | META_BLOCK_UNCOMPRESSED;
                    output.write_all(&header.to_le_bytes())?;
                    output.write_all(chunk)?;
                }
            }

            pos = end;
        }

        // Write the lookup table: array of u64 offsets
        let table_start = output.stream_position()?;
        for offset in &block_offsets {
            output.write_all(&offset.to_le_bytes())?;
        }

        Ok(table_start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn single_fragment() {
        let mut ft = FragmentTable::new();
        let mut out = Cursor::new(Vec::new());
        let (idx, off) = ft.add_fragment(b"hello", &mut out).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(off, 0);
        assert_eq!(ft.count(), 0); // not flushed yet

        ft.finish(&mut out).unwrap();
        assert_eq!(ft.count(), 1);
    }

    #[test]
    fn multiple_fragments_same_block() {
        let mut ft = FragmentTable::new();
        let mut out = Cursor::new(Vec::new());

        let (idx1, off1) = ft.add_fragment(b"aaa", &mut out).unwrap();
        let (idx2, off2) = ft.add_fragment(b"bbb", &mut out).unwrap();

        assert_eq!(idx1, 0);
        assert_eq!(off1, 0);
        assert_eq!(idx2, 0);
        assert_eq!(off2, 3);

        ft.finish(&mut out).unwrap();
        assert_eq!(ft.count(), 1); // both in one block
    }

    #[test]
    fn overflow_to_next_block() {
        let mut ft = FragmentTable::new();
        let mut out = Cursor::new(Vec::new());

        // Fill up close to block size
        let big = vec![0u8; DATA_BLOCK_SIZE as usize - 10];
        let (idx1, off1) = ft.add_fragment(&big, &mut out).unwrap();
        assert_eq!(idx1, 0);
        assert_eq!(off1, 0);

        // This should trigger a flush and go into the next block
        let small = vec![1u8; 100];
        let (idx2, off2) = ft.add_fragment(&small, &mut out).unwrap();
        assert_eq!(idx2, 1);
        assert_eq!(off2, 0);

        ft.finish(&mut out).unwrap();
        assert_eq!(ft.count(), 2);
    }

    #[test]
    fn write_table_empty() {
        let ft = FragmentTable::new();
        let mut out = Cursor::new(Vec::new());
        let offset = ft.write_table(&mut out).unwrap();
        assert_eq!(offset, 0);
    }
}
