//! Minimal v5 reference-count B+tree leaf codec.
//!
//! The writer currently supports a single-leaf REFCOUNBT. This covers normal
//! non-reflink filesystems while refusing growth that would require a split.

extern crate alloc;

use alloc::{vec, vec::Vec};

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::constants::XFS_REFCOUNT_CRC_MAGIC;

const HEADER_SIZE: usize = 56;
const CRC_OFFSET: usize = 52;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefcountRec {
    /// AG-relative starting filesystem block.
    pub start_block: u32,
    pub block_count: u32,
    pub refcount: u32,
}

impl RefcountRec {
    pub const SIZE: usize = 12;

    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            start_block: buffer.read_be_u32(0)?,
            block_count: buffer.read_be_u32(4)?,
            refcount: buffer.read_be_u32(8)?,
        })
    }

    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buffer = [0u8; Self::SIZE];
        buffer[0..4].copy_from_slice(&self.start_block.to_be_bytes());
        buffer[4..8].copy_from_slice(&self.block_count.to_be_bytes());
        buffer[8..12].copy_from_slice(&self.refcount.to_be_bytes());
        buffer
    }

    fn end(&self) -> Option<u32> {
        self.start_block.checked_add(self.block_count)
    }
}

#[derive(Debug, Clone)]
pub struct RefcountTree {
    pub records: Vec<RefcountRec>,
}

impl RefcountTree {
    pub fn parse(
        raw: &[u8],
        ag_number: u32,
        ag_block: u32,
        ag_blocks: u32,
        block_size: usize,
        sector_size: usize,
        uuid: [u8; 16],
    ) -> FsResult<Self> {
        if raw.len() != block_size || block_size < HEADER_SIZE || sector_size == 0 {
            return Err(FsError::Corrupted);
        }
        if raw.read_be_u32(0)? != XFS_REFCOUNT_CRC_MAGIC || raw.read_be_u16(4)? != 0 {
            return Err(FsError::InvalidMagic);
        }
        let num_records = raw.read_be_u16(6)? as usize;
        let capacity = (block_size - HEADER_SIZE) / RefcountRec::SIZE;
        if num_records > capacity {
            return Err(FsError::Corrupted);
        }
        let absolute = (ag_number as u64)
            .checked_mul(ag_blocks as u64)
            .and_then(|value| value.checked_add(ag_block as u64))
            .ok_or(FsError::ArithmeticOverflow)?;
        let disk_address = absolute
            .checked_mul(block_size as u64)
            .and_then(|value| value.checked_div(sector_size as u64))
            .ok_or(FsError::ArithmeticOverflow)?;
        if raw.read_be_u64(16)? != disk_address
            || raw.read_be_u32(48)? != ag_number
            || raw[32..48] != uuid
        {
            return Err(FsError::Corrupted);
        }
        let crc = raw.read_le_u32(CRC_OFFSET)?;
        crate::crc::verify_crc32c_field(raw, CRC_OFFSET, crc, true)?;

        let mut records = Vec::with_capacity(num_records);
        for index in 0..num_records {
            let offset = HEADER_SIZE + index * RefcountRec::SIZE;
            let record = RefcountRec::parse(
                raw.get(offset..offset + RefcountRec::SIZE)
                    .ok_or(FsError::Corrupted)?,
            )?;
            if record.block_count == 0
                || record.refcount == 0
                || record.end().is_none_or(|end| end > ag_blocks)
                || records.last().is_some_and(|previous: &RefcountRec| {
                    previous.end().is_none_or(|end| end > record.start_block)
                })
            {
                return Err(FsError::Corrupted);
            }
            records.push(record);
        }
        Ok(Self { records })
    }

    pub fn build(
        &self,
        ag_number: u32,
        ag_block: u32,
        ag_blocks: u32,
        block_size: usize,
        sector_size: usize,
        uuid: [u8; 16],
    ) -> FsResult<Vec<u8>> {
        let capacity = block_size.saturating_sub(HEADER_SIZE) / RefcountRec::SIZE;
        if self.records.len() > capacity || block_size < HEADER_SIZE {
            return Err(FsError::NoSpace);
        }
        let absolute = (ag_number as u64)
            .checked_mul(ag_blocks as u64)
            .and_then(|value| value.checked_add(ag_block as u64))
            .ok_or(FsError::ArithmeticOverflow)?;
        let disk_address = absolute
            .checked_mul(block_size as u64)
            .and_then(|value| value.checked_div(sector_size as u64))
            .ok_or(FsError::ArithmeticOverflow)?;
        let mut raw = vec![0u8; block_size];
        raw[0..4].copy_from_slice(&XFS_REFCOUNT_CRC_MAGIC.to_be_bytes());
        raw[6..8].copy_from_slice(&(self.records.len() as u16).to_be_bytes());
        raw[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        raw[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        raw[16..24].copy_from_slice(&disk_address.to_be_bytes());
        raw[32..48].copy_from_slice(&uuid);
        raw[48..52].copy_from_slice(&ag_number.to_be_bytes());
        for (index, record) in self.records.iter().enumerate() {
            let offset = HEADER_SIZE + index * RefcountRec::SIZE;
            raw[offset..offset + RefcountRec::SIZE].copy_from_slice(&record.to_bytes());
        }
        crate::crc::recalculate_crc_le(&mut raw, CRC_OFFSET).ok_or(FsError::BufferTooSmall)?;
        Ok(raw)
    }

    /// Reject any extent already tracked by REFCOUNBT.
    ///
    /// Normal single-owner data, metadata, and free extents are not represented
    /// in REFCOUNBT. A record therefore denotes shared data or a CoW staging
    /// extent, neither of which this writer can allocate or free safely.
    pub fn ensure_unshared(&self, start: u32, count: u32, ag_blocks: u32) -> FsResult<()> {
        if count == 0 {
            return Err(FsError::InvalidArgument);
        }
        let end = start
            .checked_add(count)
            .ok_or(FsError::ArithmeticOverflow)?;
        if end > ag_blocks {
            return Err(FsError::InvalidBlockAddress);
        }
        if self.records.iter().any(|record| {
            record
                .end()
                .is_some_and(|record_end| start < record_end && record.start_block < end)
        }) {
            return Err(FsError::NotSupported);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_round_trip_and_crc() {
        let tree = RefcountTree {
            records: vec![RefcountRec {
                start_block: 100,
                block_count: 4,
                refcount: 1,
            }],
        };
        let raw = tree.build(0, 5, 4096, 4096, 512, [0xA5; 16]).unwrap();
        let parsed = RefcountTree::parse(&raw, 0, 5, 4096, 4096, 512, [0xA5; 16]).unwrap();
        assert_eq!(parsed.records, tree.records);
        let mut corrupted = raw;
        corrupted[100] ^= 1;
        assert!(matches!(
            RefcountTree::parse(&corrupted, 0, 5, 4096, 4096, 512, [0xA5; 16]),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn shared_and_cow_extents_are_rejected() {
        let tree = RefcountTree {
            records: vec![
                RefcountRec {
                    start_block: 10,
                    block_count: 4,
                    refcount: 2,
                },
                RefcountRec {
                    start_block: 1 << 31,
                    block_count: 4,
                    refcount: 1,
                },
            ],
        };
        tree.ensure_unshared(20, 4, u32::MAX).unwrap();
        assert!(matches!(
            tree.ensure_unshared(12, 4, u32::MAX),
            Err(FsError::NotSupported)
        ));
        assert!(matches!(
            tree.ensure_unshared(1 << 31, 2, u32::MAX),
            Err(FsError::NotSupported)
        ));
    }
}
