/// Metadata block writer and data block writer.
///
/// Metadata blocks are 8 KiB max, prefixed with a u16 length header.
/// Data blocks are 128 KiB, zstd-compressed.
use std::io::{self, Seek, Write};

use rayon::prelude::*;

use crate::format::{
    DATA_BLOCK_SIZE, DATA_BLOCK_UNCOMPRESSED, METADATA_BLOCK_SIZE, META_BLOCK_UNCOMPRESSED,
};

const ZSTD_LEVEL: i32 = 3;

/// Compresses `data` with zstd. Returns None if compressed is not smaller.
fn zstd_compress(data: &[u8]) -> Option<Vec<u8>> {
    let compressed = zstd::bulk::compress(data, ZSTD_LEVEL).ok()?;
    if compressed.len() < data.len() {
        Some(compressed)
    } else {
        None
    }
}

/// Accumulates inode/directory metadata and writes 8 KiB compressed blocks.
///
/// Callers write structured data via `write()`, then query `position()` to
/// capture inode references before flushing.
pub struct MetadataWriter {
    /// Internal accumulation buffer.
    buf: Vec<u8>,
    /// Compressed blocks accumulated so far (not yet written to output).
    blocks: Vec<Vec<u8>>,
    /// Total bytes of compressed block data written so far.
    blocks_byte_len: u64,
}

impl MetadataWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(METADATA_BLOCK_SIZE),
            blocks: Vec::new(),
            blocks_byte_len: 0,
        }
    }

    /// Returns the current position as (block_byte_offset, offset_within_block).
    /// `block_byte_offset` is relative to the start of this table when written.
    pub fn position(&self) -> (u64, u16) {
        (self.blocks_byte_len, self.buf.len() as u16)
    }

    /// Append raw bytes to the metadata stream. Automatically flushes
    /// complete 8 KiB blocks.
    pub fn write(&mut self, data: &[u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let remaining_in_block = METADATA_BLOCK_SIZE - self.buf.len();
            let to_copy = remaining_in_block.min(data.len() - offset);
            self.buf.extend_from_slice(&data[offset..offset + to_copy]);
            offset += to_copy;

            if self.buf.len() == METADATA_BLOCK_SIZE {
                self.flush_block_internal();
            }
        }
    }

    fn flush_block_internal(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let raw = std::mem::take(&mut self.buf);
        let block = match zstd_compress(&raw) {
            Some(compressed) => {
                let size = compressed.len() as u16;
                let mut out = Vec::with_capacity(2 + compressed.len());
                out.extend_from_slice(&size.to_le_bytes());
                out.extend_from_slice(&compressed);
                out
            }
            None => {
                let size = raw.len() as u16 | META_BLOCK_UNCOMPRESSED;
                let mut out = Vec::with_capacity(2 + raw.len());
                out.extend_from_slice(&size.to_le_bytes());
                out.extend_from_slice(&raw);
                out
            }
        };
        self.blocks_byte_len += block.len() as u64;
        self.blocks.push(block);
        self.buf = Vec::with_capacity(METADATA_BLOCK_SIZE);
    }

    /// Flush remaining data and write all blocks to `output`.
    /// Returns the byte offset in `output` where the table starts.
    pub fn finish<W: Write + Seek>(&mut self, output: &mut W) -> io::Result<u64> {
        self.flush_block_internal();
        let start = output.stream_position()?;
        for block in self.blocks.drain(..) {
            output.write_all(&block)?;
        }
        self.blocks_byte_len = 0;
        Ok(start)
    }
}

/// A compressed (or sparse/uncompressed) data block ready to be written.
pub enum CompressedBlock {
    /// All-zero block — nothing written, stored as size 0.
    Sparse,
    /// Compressed block — data is the zstd-compressed bytes.
    Compressed(Vec<u8>),
    /// Uncompressed block — compression wasn't beneficial.
    Uncompressed(Vec<u8>),
}

/// Pre-compressed file data ready for sequential writing.
pub struct CompressedFile {
    /// Index into the caller's file list (to map back results).
    pub file_idx: usize,
    /// Compressed blocks in order.
    pub blocks: Vec<CompressedBlock>,
}

/// Compress multiple files' data blocks in parallel using rayon.
///
/// Takes a list of `(file_idx, file_data)` pairs. Returns compressed blocks
/// for each file, preserving file order and block order within each file.
/// The actual writing to output must be done sequentially afterwards.
pub fn compress_files_parallel(files: &[(usize, &[u8])]) -> Vec<CompressedFile> {
    let block_sz = DATA_BLOCK_SIZE as usize;

    // Build a flat list of (file_list_index, chunk) for all blocks across all files
    let all_chunks: Vec<(usize, &[u8])> = files
        .iter()
        .enumerate()
        .flat_map(|(list_idx, (_file_idx, data))| {
            let mut chunks = Vec::new();
            let mut offset = 0;
            while offset < data.len() {
                let end = (offset + block_sz).min(data.len());
                chunks.push((list_idx, &data[offset..end]));
                offset = end;
            }
            chunks
        })
        .collect();

    // Compress all chunks in parallel
    let compressed_chunks: Vec<(usize, CompressedBlock)> = all_chunks
        .par_iter()
        .map(|&(list_idx, chunk)| {
            let block = if chunk.iter().all(|&b| b == 0) {
                CompressedBlock::Sparse
            } else {
                match zstd_compress(chunk) {
                    Some(compressed) => CompressedBlock::Compressed(compressed),
                    None => CompressedBlock::Uncompressed(chunk.to_vec()),
                }
            };
            (list_idx, block)
        })
        .collect();

    // Group blocks back into per-file results, preserving order
    let mut results: Vec<CompressedFile> = files
        .iter()
        .map(|(file_idx, _)| CompressedFile {
            file_idx: *file_idx,
            blocks: Vec::new(),
        })
        .collect();

    for (list_idx, block) in compressed_chunks {
        results[list_idx].blocks.push(block);
    }

    results
}

/// Write pre-compressed file blocks to output sequentially.
///
/// Returns `(start_byte_offset, block_sizes)` for inode metadata.
pub fn write_compressed_file<W: Write + Seek>(
    blocks: &CompressedFile,
    output: &mut W,
) -> io::Result<(u64, Vec<u32>)> {
    let start = output.stream_position()?;
    let mut block_sizes = Vec::new();

    for block in &blocks.blocks {
        match block {
            CompressedBlock::Sparse => {
                block_sizes.push(0);
            }
            CompressedBlock::Compressed(data) => {
                output.write_all(data)?;
                block_sizes.push(data.len() as u32);
            }
            CompressedBlock::Uncompressed(data) => {
                output.write_all(data)?;
                block_sizes.push(data.len() as u32 | DATA_BLOCK_UNCOMPRESSED);
            }
        }
    }

    Ok((start, block_sizes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn metadata_writer_small() {
        let mut mw = MetadataWriter::new();
        mw.write(&[0xAB; 100]);
        let (blk, off) = mw.position();
        assert_eq!(blk, 0);
        assert_eq!(off, 100);

        let mut out = Cursor::new(Vec::new());
        let start = mw.finish(&mut out).unwrap();
        assert_eq!(start, 0);
        let data = out.into_inner();
        // Should have one block: 2-byte header + payload
        assert!(data.len() > 2);
        let header = u16::from_le_bytes([data[0], data[1]]);
        // Either compressed or uncompressed, check the size makes sense
        let is_uncompressed = header & META_BLOCK_UNCOMPRESSED != 0;
        let size = (header & !META_BLOCK_UNCOMPRESSED) as usize;
        if is_uncompressed {
            assert_eq!(size, 100);
        } else {
            assert!(size < 100);
        }
        assert_eq!(data.len(), 2 + size);
    }

    #[test]
    fn metadata_writer_multi_block() {
        let mut mw = MetadataWriter::new();
        // Write more than one block worth
        mw.write(&[0x42; METADATA_BLOCK_SIZE + 100]);
        let (blk, off) = mw.position();
        // First block has been flushed
        assert!(blk > 0);
        assert_eq!(off, 100);
    }

    #[test]
    fn data_block_writer_small() {
        let data = vec![0x55; 1000];
        let files = vec![(0, data.as_slice())];
        let compressed = compress_files_parallel(&files);
        assert_eq!(compressed.len(), 1);
        assert_eq!(compressed[0].blocks.len(), 1);

        let mut out = Cursor::new(Vec::new());
        let (start, sizes) = write_compressed_file(&compressed[0], &mut out).unwrap();
        assert_eq!(start, 0);
        assert_eq!(sizes.len(), 1);
    }

    #[test]
    fn data_block_writer_multi() {
        // 3 full blocks + partial
        let data = vec![0x77; DATA_BLOCK_SIZE as usize * 3 + 5000];
        let files = vec![(0, data.as_slice())];
        let compressed = compress_files_parallel(&files);
        assert_eq!(compressed[0].blocks.len(), 4); // 3 full + 1 partial

        let mut out = Cursor::new(Vec::new());
        let (_, sizes) = write_compressed_file(&compressed[0], &mut out).unwrap();
        assert_eq!(sizes.len(), 4);
    }
}
