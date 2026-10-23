// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Pure-Rust codec for packed Solaris/OpenZFS name-value lists (nvlists).

[`NvList::unpack`] decodes both the native and XDR encodings; [`NvList::pack`]
encodes the native one (the only encoding the `/dev/zfs` ioctls accept on
input). The format is defined by `nvs_native_*` in `doc/reference/nvpair.c`
(vendored from OpenZFS 2.2.2):

```text
[0..4)   stream header: u8 encoding (0=native, 1=xdr), u8 endian
         (1=little, 0=big), 2 reserved bytes
[4..12)  root nvlist only: i32 nvl_version, u32 nvl_nvflag
then a sequence of nvpairs, terminated by an i32 zero:
  +0   i32 nvp_size        total size of this nvpair blob
  +4   i16 nvp_name_sz     name length including NUL
  +6   i16 nvp_reserve
  +8   i32 nvp_value_elem  element count for array types
  +12  i32 nvp_type        data_type_t
  +16  name bytes (nvp_name_sz, NUL-terminated)
  +align8(16 + name_sz)  value data, up to nvp_size
```

Embedded nvlists do NOT re-encode version/nvflag in the stream; the
parent nvpair's value area carries a copy of the in-memory `nvlist_t`
(24 bytes) whose first 8 bytes hold version/nvflag. The child's pairs
follow the parent nvpair blob in the stream, ending with their own
4-byte zero terminator. NVLIST_ARRAY values hold `nelem` 8-byte pointer
placeholders plus `nelem` nvlist_t copies, followed in the stream by
each child's pair sequence. STRING_ARRAY values hold `nelem` 8-byte
placeholders followed by the packed NUL-terminated strings.
*/

use thiserror::Error;

/// `NV_UNIQUE_NAME` flag bit of `nvl_nvflag`.
pub const NV_UNIQUE_NAME: u32 = 0x1;

const NVPAIR_HDR_SIZE: usize = 16;
const NVLIST_STRUCT_SIZE: usize = 24;
const MAX_DEPTH: usize = 64;

#[derive(Debug, Error)]
pub enum NvError {
    #[rustfmt::skip]
    #[error("buffer truncated: need {need} bytes at offset {at}, have {have}")]
    Truncated { at: usize, need: usize, have: usize },
    #[error("unsupported nvlist encoding {0} (native and XDR supported)")]
    UnsupportedEncoding(u8),
    #[error("unsupported endianness {0}")]
    UnsupportedEndian(u8),
    #[error("unsupported nvlist version {0} (only version 0 is supported)")]
    UnsupportedVersion(i32),
    #[error("invalid nvpair size {size} at offset {at}")]
    BadPairSize { at: usize, size: i64 },
    #[error("invalid nvpair name (name_sz {0})")]
    BadName(i16),
    #[error("nvpair array element count {0} is negative")]
    BadArrayCount(i64),
    #[error("xdr array count {count} disagrees with declared nelem {nelem}")]
    ArrayCountMismatch { count: usize, nelem: usize },
    #[error("nvpair size arithmetic overflowed (element count {0})")]
    Overflow(usize),
    #[error("string value not NUL-terminated in pair '{0}'")]
    BadString(String),
    #[rustfmt::skip]
    #[error("value for '{name}' ({need} bytes) exceeds nvpair bounds ({have} bytes)")]
    ValueOverflow { name: String, need: usize, have: usize },
    #[error("nvlist nesting deeper than {MAX_DEPTH}")]
    TooDeep,
    #[error("cannot encode '{0}': name/value size exceeds the wire format's field width")]
    TooBigToPack(String),
    #[error("cannot encode '{0}': embedded NUL in name or string value")]
    EmbeddedNul(String),
}

type Result<T> = std::result::Result<T, NvError>;

/// A decoded nvpair value. Variants mirror `data_type_t`.
#[derive(Debug, Clone, PartialEq)]
pub enum NvData {
    /// DATA_TYPE_BOOLEAN: a valueless flag whose presence is the information.
    BooleanFlag,
    Boolean(bool),
    Byte(u8),
    Int8(i8),
    Uint8(u8),
    Int16(i16),
    Uint16(u16),
    Int32(i32),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    HrTime(i64),
    Double(f64),
    Str(String),
    ByteArray(Vec<u8>),
    Int8Array(Vec<i8>),
    Uint8Array(Vec<u8>),
    Int16Array(Vec<i16>),
    Uint16Array(Vec<u16>),
    Int32Array(Vec<i32>),
    Uint32Array(Vec<u32>),
    Int64Array(Vec<i64>),
    Uint64Array(Vec<u64>),
    BooleanArray(Vec<bool>),
    StrArray(Vec<String>),
    List(NvList),
    ListArray(Vec<NvList>),
    /// A data_type_t we don't know; raw value bytes are preserved.
    Unknown {
        dtype: i32,
        raw: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct NvPair {
    pub name: String,
    pub data: NvData,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NvList {
    pub version: i32,
    pub nvflag: u32,
    pub pairs: Vec<NvPair>,
}

impl Default for NvList {
    /// An empty nvlist carrying `NV_UNIQUE_NAME`, matching [`NvList::new`].
    fn default() -> Self {
        Self::new()
    }
}

// data_type_t constants (doc/reference/nvpair.h)
const DT_BOOLEAN: i32 = 1;
const DT_BYTE: i32 = 2;
const DT_INT16: i32 = 3;
const DT_UINT16: i32 = 4;
const DT_INT32: i32 = 5;
const DT_UINT32: i32 = 6;
const DT_INT64: i32 = 7;
const DT_UINT64: i32 = 8;
const DT_STRING: i32 = 9;
const DT_BYTE_ARRAY: i32 = 10;
const DT_INT16_ARRAY: i32 = 11;
const DT_UINT16_ARRAY: i32 = 12;
const DT_INT32_ARRAY: i32 = 13;
const DT_UINT32_ARRAY: i32 = 14;
const DT_INT64_ARRAY: i32 = 15;
const DT_UINT64_ARRAY: i32 = 16;
const DT_STRING_ARRAY: i32 = 17;
const DT_HRTIME: i32 = 18;
const DT_NVLIST: i32 = 19;
const DT_NVLIST_ARRAY: i32 = 20;
const DT_BOOLEAN_VALUE: i32 = 21;
const DT_INT8: i32 = 22;
const DT_UINT8: i32 = 23;
const DT_BOOLEAN_ARRAY: i32 = 24;
const DT_INT8_ARRAY: i32 = 25;
const DT_UINT8_ARRAY: i32 = 26;
const DT_DOUBLE: i32 = 27;

const fn align8(n: usize) -> usize {
    (n + 7) & !7
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    #[rustfmt::skip]
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(NvError::Truncated { at: self.pos, need: n, have: self.remaining() });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    #[rustfmt::skip]
    fn peek_i32(&self) -> Result<i32> {
        if self.remaining() < 4 {
            return Err(NvError::Truncated { at: self.pos, need: 4, have: self.remaining() });
        }
        Ok(i32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap()))
    }

    // XDR payloads are big-endian regardless of host order.

    fn read_i32_be(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn read_u32_be(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn read_u64_be(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// XDR string: u32 length (no NUL), bytes, padded to a 4-byte boundary.
    fn read_xdr_string(&mut self) -> Result<String> {
        let len = self.read_u32_be()? as usize;
        let bytes = self.take(len)?;
        if bytes.contains(&0) {
            return Err(NvError::EmbeddedNul(String::from_utf8_lossy(bytes).into_owned()));
        }
        let s = String::from_utf8_lossy(bytes).into_owned();
        self.take(xdr_pad(len))?;
        Ok(s)
    }
}

/// Bytes of padding XDR adds after `len` bytes of payload.
const fn xdr_pad(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

impl NvList {
    /// Decode a packed nvlist (with stream header) in native or XDR encoding.
    pub fn unpack(buf: &[u8]) -> Result<NvList> {
        let mut cur = Cursor { buf, pos: 0 };
        let hdr = cur.take(4)?;
        match hdr[0] {
            0 => {
                // nvs_header_t.nvh_endian: 1 = little. Big-endian native
                // streams only occur on big-endian hosts, not targeted yet.
                if hdr[1] != 1 {
                    return Err(NvError::UnsupportedEndian(hdr[1]));
                }
                let version = cur.read_i32()?;
                check_version(version)?;
                let nvflag = cur.read_u32()?;
                let pairs = decode_pairs(&mut cur, 0)?;
                Ok(NvList { version, nvflag, pairs })
            }
            // XDR payload is big-endian on the wire regardless of the
            // host-endianness recorded in the header byte.
            1 => decode_xdr_list(&mut cur, 0),
            other => Err(NvError::UnsupportedEncoding(other)),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &NvPair> {
        self.pairs.iter()
    }

    pub fn get(&self, name: &str) -> Option<&NvData> {
        /*
        Duplicate names resolve to the LAST occurrence, matching the kernel:
        an NV_UNIQUE_NAME decode unlinks the earlier duplicate
        (nvt_add_nvpair, nvpair.c), so a hostile config carrying two `guid`
        pairs must be read the way the kernel would import it.
        */
        self.pairs.iter().rfind(|p| p.name == name).map(|p| &p.data)
    }

    pub fn get_u64(&self, name: &str) -> Option<u64> {
        match self.get(name)? {
            NvData::Uint64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_str(&self, name: &str) -> Option<&str> {
        match self.get(name)? {
            NvData::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn get_list(&self, name: &str) -> Option<&NvList> {
        match self.get(name)? {
            NvData::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn get_list_array(&self, name: &str) -> Option<&[NvList]> {
        match self.get(name)? {
            NvData::ListArray(a) => Some(a),
            _ => None,
        }
    }

    pub fn get_u64_array(&self, name: &str) -> Option<&[u64]> {
        match self.get(name)? {
            NvData::Uint64Array(a) => Some(a),
            _ => None,
        }
    }

    /* ------------------------------- building ---------------------------- */

    /**
    An empty nvlist carrying `NV_UNIQUE_NAME` — the flag the kernel
    expects on lists handed in through the `/dev/zfs` ioctl interface.
    */
    pub fn new() -> NvList {
        NvList { version: 0, nvflag: NV_UNIQUE_NAME, pairs: Vec::new() }
    }

    /// Append a pair. When `NV_UNIQUE_NAME` is set (the default from
    /// [`NvList::new`]), any earlier pair with the same name is removed
    /// first, matching `nvlist_add_common` (`doc/reference/nvpair.c`).
    /// Returns `&mut self` for chaining.
    pub fn push(&mut self, name: impl Into<String>, data: NvData) -> &mut Self {
        let name = name.into();
        if self.nvflag & NV_UNIQUE_NAME != 0 {
            self.pairs.retain(|p| p.name != name);
        }
        self.pairs.push(NvPair { name, data });
        self
    }

    pub fn add_u64(&mut self, name: impl Into<String>, v: u64) -> &mut Self {
        self.push(name, NvData::Uint64(v))
    }

    pub fn add_str(&mut self, name: impl Into<String>, v: impl Into<String>) -> &mut Self {
        self.push(name, NvData::Str(v.into()))
    }

    pub fn add_boolean(&mut self, name: impl Into<String>, v: bool) -> &mut Self {
        self.push(name, NvData::Boolean(v))
    }

    /// A valueless `DATA_TYPE_BOOLEAN` flag (presence is the information).
    pub fn add_bool_flag(&mut self, name: impl Into<String>) -> &mut Self {
        self.push(name, NvData::BooleanFlag)
    }

    pub fn add_i32(&mut self, name: impl Into<String>, v: i32) -> &mut Self {
        self.push(name, NvData::Int32(v))
    }

    pub fn add_byte_array(&mut self, name: impl Into<String>, v: Vec<u8>) -> &mut Self {
        self.push(name, NvData::ByteArray(v))
    }

    /// DATA_TYPE_UINT8_ARRAY — distinct from BYTE_ARRAY on the wire, and what
    /// the kernel's `nvlist_lookup_uint8_array` consumers (wkeydata) require.
    pub fn add_uint8_array(&mut self, name: impl Into<String>, v: Vec<u8>) -> &mut Self {
        self.push(name, NvData::Uint8Array(v))
    }

    pub fn add_nvlist(&mut self, name: impl Into<String>, v: NvList) -> &mut Self {
        self.push(name, NvData::List(v))
    }

    pub fn add_str_array(&mut self, name: impl Into<String>, v: Vec<String>) -> &mut Self {
        self.push(name, NvData::StrArray(v))
    }

    /**
    Pack into the native little-endian wire format consumed by the
    `/dev/zfs` ioctls (the inverse of [`NvList::unpack`]'s native path).
    Native is the only encoding the kernel accepts on input.

    Errors on names/string values with interior NULs and on sizes that would
    truncate the i16/i32 wire fields — the kernel would otherwise silently
    misread (or wholesale reject) the stream. Note that `Double` and
    `Unknown` pairs, while packable, are rejected by the *kernel* decoder
    (DATA_TYPE_DOUBLE is compiled out under _KERNEL; unknown types EFAULT),
    so strip them from lists destined for write ioctls.
    */
    pub fn pack(&self) -> Result<Vec<u8>> {
        check_version(self.version)?;
        let mut out = Vec::with_capacity(16 + self.pairs.len() * 32);
        out.extend_from_slice(&[0u8, 1, 0, 0]); // NV_ENCODE_NATIVE, little-endian
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.nvflag.to_le_bytes());
        encode_pairs(&mut out, &self.pairs, 0)?;
        Ok(out)
    }
}

fn check_version(version: i32) -> Result<()> {
    if version != 0 {
        return Err(NvError::UnsupportedVersion(version));
    }
    Ok(())
}

/// Decode a sequence of nvpairs up to and including the zero terminator.
fn decode_pairs(cur: &mut Cursor, depth: usize) -> Result<Vec<NvPair>> {
    if depth > MAX_DEPTH {
        return Err(NvError::TooDeep);
    }
    let mut pairs = Vec::new();
    loop {
        let size = cur.peek_i32()?;
        if size == 0 {
            cur.take(4)?;
            return Ok(pairs);
        }
        if size < NVPAIR_HDR_SIZE as i32 || size as usize > cur.remaining() {
            return Err(NvError::BadPairSize {
                at: cur.pos,
                size: size as i64,
            });
        }
        let blob = cur.take(size as usize)?;
        let name_sz = i16::from_le_bytes(blob[4..6].try_into().unwrap());
        let value_elem = i32::from_le_bytes(blob[8..12].try_into().unwrap());
        let dtype = i32::from_le_bytes(blob[12..16].try_into().unwrap());

        // the name is `name_sz` bytes including a trailing NUL; require it
        // to fit, be NUL-terminated, and carry no interior NULs
        // (i_validate_nvpair_name: strlen(NVP_NAME(nvp)) == nvp_name_sz - 1).
        if name_sz < 1
            || NVPAIR_HDR_SIZE + name_sz as usize > blob.len()
            || blob[NVPAIR_HDR_SIZE + name_sz as usize - 1] != 0
        {
            return Err(NvError::BadName(name_sz));
        }
        let name_bytes = &blob[NVPAIR_HDR_SIZE..NVPAIR_HDR_SIZE + name_sz as usize - 1];
        if name_bytes.contains(&0) {
            return Err(NvError::BadName(name_sz));
        }
        let name = String::from_utf8_lossy(name_bytes).into_owned();

        // nvp_value_elem is a count; negative is malformed (was silently
        // coerced to 0, hiding corruption).
        if value_elem < 0 {
            return Err(NvError::BadArrayCount(value_elem as i64));
        }
        let val_off = align8(NVPAIR_HDR_SIZE + name_sz as usize);
        let value = blob.get(val_off..).unwrap_or(&[]);
        let nelem = value_elem as usize;

        let data = decode_value(cur, &name, dtype, nelem, value, depth)?;
        pairs.push(NvPair { name, data });
    }
}

/// Decode one nvpair's value. `value` is the value region inside the nvpair
/// blob; embedded nvlist children are pulled from the stream via `cur`.
fn decode_value(
    cur: &mut Cursor,
    name: &str,
    dtype: i32,
    nelem: usize,
    value: &[u8],
    depth: usize,
) -> Result<NvData> {
    let need = |n: usize| -> Result<&[u8]> {
        value.get(..n).ok_or_else(|| NvError::ValueOverflow {
            name: name.to_string(),
            need: n,
            have: value.len(),
        })
    };
    let scalar_array = |elem_sz: usize| -> Result<std::slice::ChunksExact<'_, u8>> {
        let raw = need(nelem.checked_mul(elem_sz).ok_or(NvError::Overflow(nelem))?)?;
        Ok(raw.chunks_exact(elem_sz))
    };

    Ok(match dtype {
        DT_BOOLEAN => NvData::BooleanFlag,
        DT_BOOLEAN_VALUE => NvData::Boolean(i32::from_le_bytes(need(4)?.try_into().unwrap()) != 0),
        DT_BYTE => NvData::Byte(need(1)?[0]),
        DT_INT8 => NvData::Int8(need(1)?[0] as i8),
        DT_UINT8 => NvData::Uint8(need(1)?[0]),
        DT_INT16 => NvData::Int16(i16::from_le_bytes(need(2)?.try_into().unwrap())),
        DT_UINT16 => NvData::Uint16(u16::from_le_bytes(need(2)?.try_into().unwrap())),
        DT_INT32 => NvData::Int32(i32::from_le_bytes(need(4)?.try_into().unwrap())),
        DT_UINT32 => NvData::Uint32(u32::from_le_bytes(need(4)?.try_into().unwrap())),
        DT_INT64 => NvData::Int64(i64::from_le_bytes(need(8)?.try_into().unwrap())),
        DT_UINT64 => NvData::Uint64(u64::from_le_bytes(need(8)?.try_into().unwrap())),
        DT_HRTIME => NvData::HrTime(i64::from_le_bytes(need(8)?.try_into().unwrap())),
        DT_DOUBLE => NvData::Double(f64::from_le_bytes(need(8)?.try_into().unwrap())),
        DT_STRING => NvData::Str(read_cstr(value, name)?.0),
        DT_BYTE_ARRAY => NvData::ByteArray(need(nelem)?.to_vec()),
        DT_UINT8_ARRAY => NvData::Uint8Array(need(nelem)?.to_vec()),
        DT_INT8_ARRAY => NvData::Int8Array(need(nelem)?.iter().map(|&b| b as i8).collect()),
        DT_INT16_ARRAY => NvData::Int16Array(
            scalar_array(2)?
                .map(|c| i16::from_le_bytes(c.try_into().unwrap()))
                .collect(),
        ),
        DT_UINT16_ARRAY => NvData::Uint16Array(
            scalar_array(2)?
                .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
                .collect(),
        ),
        DT_INT32_ARRAY => NvData::Int32Array(
            scalar_array(4)?
                .map(|c| i32::from_le_bytes(c.try_into().unwrap()))
                .collect(),
        ),
        DT_UINT32_ARRAY => NvData::Uint32Array(
            scalar_array(4)?
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect(),
        ),
        DT_INT64_ARRAY => NvData::Int64Array(
            scalar_array(8)?
                .map(|c| i64::from_le_bytes(c.try_into().unwrap()))
                .collect(),
        ),
        DT_UINT64_ARRAY => NvData::Uint64Array(
            scalar_array(8)?
                .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                .collect(),
        ),
        // boolean_t array elements are 4 bytes each
        DT_BOOLEAN_ARRAY => NvData::BooleanArray(
            scalar_array(4)?
                .map(|c| i32::from_le_bytes(c.try_into().unwrap()) != 0)
                .collect(),
        ),
        DT_STRING_ARRAY => {
            // nelem pointer placeholders, then packed NUL-terminated strings
            let placeholders = nelem.checked_mul(8).ok_or(NvError::Overflow(nelem))?;
            let mut rest = need(placeholders).map(|_| &value[placeholders..])?;
            let mut strs = Vec::with_capacity(nelem);
            for _ in 0..nelem {
                let (s, consumed) = read_cstr(rest, name)?;
                strs.push(s);
                rest = &rest[consumed..];
            }
            NvData::StrArray(strs)
        }
        DT_NVLIST => {
            let hdr = need(NVLIST_STRUCT_SIZE)?;
            let version = i32::from_le_bytes(hdr[0..4].try_into().unwrap());
            check_version(version)?;
            let nvflag = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
            let pairs = decode_pairs(cur, depth + 1)?;
            NvData::List(NvList {
                version,
                nvflag,
                pairs,
            })
        }
        DT_NVLIST_ARRAY => {
            // nelem pointer placeholders, then nelem nvlist_t struct copies;
            // each child's pair stream follows in order.
            let total = nelem.checked_mul(8 + NVLIST_STRUCT_SIZE).ok_or(NvError::Overflow(nelem))?;
            let hdrs = need(total)?;
            let mut lists = Vec::with_capacity(nelem);
            for i in 0..nelem {
                let off = nelem * 8 + i * NVLIST_STRUCT_SIZE;
                let version = i32::from_le_bytes(hdrs[off..off + 4].try_into().unwrap());
                check_version(version)?;
                let nvflag = u32::from_le_bytes(hdrs[off + 4..off + 8].try_into().unwrap());
                let pairs = decode_pairs(cur, depth + 1)?;
                lists.push(NvList {
                    version,
                    nvflag,
                    pairs,
                });
            }
            NvData::ListArray(lists)
        }
        _ => NvData::Unknown {
            dtype,
            raw: value.to_vec(),
        },
    })
}

/// Read a NUL-terminated string from the start of `buf`; returns the string
/// and the number of bytes consumed (including the NUL).
fn read_cstr(buf: &[u8], pair_name: &str) -> Result<(String, usize)> {
    match buf.iter().position(|&b| b == 0) {
        Some(n) => Ok((String::from_utf8_lossy(&buf[..n]).into_owned(), n + 1)),
        None => Err(NvError::BadString(pair_name.to_string())),
    }
}

/* ----------------------------- native encoding --------------------------- */

/// Encode a pair sequence and its 4-byte zero terminator (used for the root
/// list and for every embedded child stream).
fn encode_pairs(out: &mut Vec<u8>, pairs: &[NvPair], depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(NvError::TooDeep);
    }
    for p in pairs {
        encode_pair(out, &p.name, &p.data, depth)?;
    }
    out.extend_from_slice(&0i32.to_le_bytes()); // terminator
    Ok(())
}

/**
Encode one nvpair blob directly into `out`, then — for embedded nvlists —
its child pair stream, which the kernel format places immediately after the
parent blob. `nvp_size = NV_ALIGN(16 + name_sz) + NV_ALIGN(value_sz)` per
`NVP_SIZE_CALC`, patched into the header once the value has been written.
*/
fn encode_pair(out: &mut Vec<u8>, name: &str, data: &NvData, depth: usize) -> Result<()> {
    match data {
        NvData::List(list) => check_version(list.version)?,
        NvData::ListArray(lists) => {
            for list in lists {
                check_version(list.version)?;
            }
        }
        _ => {}
    }
    /*
    The wire format is NUL-delimited: an interior NUL makes the kernel's
    decoder see a shorter string (silently changing the value — its
    validator recomputes strlen and the align classes can still agree) or
    reject the whole list. Refuse to encode one.
    */
    let has_nul = |s: &str| s.as_bytes().contains(&0);
    let value_nul = match data {
        NvData::Str(s) => has_nul(s),
        NvData::StrArray(v) => v.iter().any(|s| has_nul(s)),
        _ => false,
    };
    if has_nul(name) || value_nul {
        return Err(NvError::EmbeddedNul(name.to_string()));
    }
    let name_sz = name.len() + 1;
    if name_sz > i16::MAX as usize {
        return Err(NvError::TooBigToPack(name.to_string()));
    }
    let val_off = align8(NVPAIR_HDR_SIZE + name_sz);
    let pair_start = out.len();

    // Reserve header + NUL-terminated name padded to 8-byte alignment;
    // nvp_size, nvp_value_elem, and nvp_type are patched once the value is written.
    out.extend_from_slice(&0i32.to_le_bytes()); // nvp_size placeholder
    out.extend_from_slice(&(name_sz as i16).to_le_bytes());
    out.extend_from_slice(&0i16.to_le_bytes()); // nvp_reserve
    out.extend_from_slice(&0i32.to_le_bytes()); // nvp_value_elem placeholder
    out.extend_from_slice(&0i32.to_le_bytes()); // nvp_type placeholder
    out.extend_from_slice(name.as_bytes());
    out.resize(pair_start + val_off, 0); // trailing NUL + name padding

    let val_start = out.len();
    let (dtype, nelem) = write_value(out, data);
    let val_len = out.len() - val_start;
    let aligned_val_len = align8(val_len);
    out.resize(val_start + aligned_val_len, 0); // value padding

    let size = val_off + aligned_val_len;
    /*
    nvp_name_sz is i16, nvp_size and nvp_value_elem i32: an oversized name
    or value must error here, not wrap on the cast — a wrapped nvp_size can
    turn small-positive and desync the kernel's framing of the whole stream.
    */
    if size > i32::MAX as usize || nelem > i32::MAX as usize {
        return Err(NvError::TooBigToPack(name.to_string()));
    }
    out[pair_start..pair_start + 4].copy_from_slice(&(size as i32).to_le_bytes());
    out[pair_start + 8..pair_start + 12].copy_from_slice(&(nelem as i32).to_le_bytes());
    out[pair_start + 12..pair_start + 16].copy_from_slice(&dtype.to_le_bytes());

    match data {
        NvData::List(l) => encode_pairs(out, &l.pairs, depth + 1)?,
        NvData::ListArray(a) => {
            for l in a {
                encode_pairs(out, &l.pairs, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/**
Append the unpadded wire representation of `data` directly to `out` and
return `(data_type_t, nvp_value_elem)`. [`encode_pair`] applies the
`NV_ALIGN` padding that `NVP_SIZE_CALC` accounts for.
*/
fn write_value(out: &mut Vec<u8>, data: &NvData) -> (i32, usize) {
    fn flat<T: Copy, const N: usize>(out: &mut Vec<u8>, v: &[T], f: impl Fn(T) -> [u8; N]) {
        out.reserve(v.len() * N);
        for &x in v {
            out.extend_from_slice(&f(x));
        }
    }
    match data {
        NvData::BooleanFlag => (DT_BOOLEAN, 0),
        // boolean_t is a 4-byte int on the wire
        NvData::Boolean(b) => {
            out.extend_from_slice(&(*b as i32).to_le_bytes());
            (DT_BOOLEAN_VALUE, 1)
        }
        NvData::Byte(v) => {
            out.push(*v);
            (DT_BYTE, 1)
        }
        NvData::Int8(v) => {
            out.push(*v as u8);
            (DT_INT8, 1)
        }
        NvData::Uint8(v) => {
            out.push(*v);
            (DT_UINT8, 1)
        }
        NvData::Int16(v) => {
            out.extend_from_slice(&v.to_le_bytes());
            (DT_INT16, 1)
        }
        NvData::Uint16(v) => {
            out.extend_from_slice(&v.to_le_bytes());
            (DT_UINT16, 1)
        }
        NvData::Int32(v) => {
            out.extend_from_slice(&v.to_le_bytes());
            (DT_INT32, 1)
        }
        NvData::Uint32(v) => {
            out.extend_from_slice(&v.to_le_bytes());
            (DT_UINT32, 1)
        }
        NvData::Int64(v) => {
            out.extend_from_slice(&v.to_le_bytes());
            (DT_INT64, 1)
        }
        NvData::Uint64(v) => {
            out.extend_from_slice(&v.to_le_bytes());
            (DT_UINT64, 1)
        }
        NvData::HrTime(v) => {
            out.extend_from_slice(&v.to_le_bytes());
            (DT_HRTIME, 1)
        }
        NvData::Double(v) => {
            out.extend_from_slice(&v.to_le_bytes());
            (DT_DOUBLE, 1)
        }
        NvData::Str(s) => {
            out.extend_from_slice(s.as_bytes());
            out.push(0);
            (DT_STRING, 1)
        }
        NvData::ByteArray(v) => {
            out.extend_from_slice(v);
            (DT_BYTE_ARRAY, v.len())
        }
        NvData::Uint8Array(v) => {
            out.extend_from_slice(v);
            (DT_UINT8_ARRAY, v.len())
        }
        NvData::Int8Array(v) => {
            out.extend(v.iter().map(|&x| x as u8));
            (DT_INT8_ARRAY, v.len())
        }
        NvData::Int16Array(v) => {
            flat(out, v, i16::to_le_bytes);
            (DT_INT16_ARRAY, v.len())
        }
        NvData::Uint16Array(v) => {
            flat(out, v, u16::to_le_bytes);
            (DT_UINT16_ARRAY, v.len())
        }
        NvData::Int32Array(v) => {
            flat(out, v, i32::to_le_bytes);
            (DT_INT32_ARRAY, v.len())
        }
        NvData::Uint32Array(v) => {
            flat(out, v, u32::to_le_bytes);
            (DT_UINT32_ARRAY, v.len())
        }
        NvData::Int64Array(v) => {
            flat(out, v, i64::to_le_bytes);
            (DT_INT64_ARRAY, v.len())
        }
        NvData::Uint64Array(v) => {
            flat(out, v, u64::to_le_bytes);
            (DT_UINT64_ARRAY, v.len())
        }
        // boolean_t array elements are 4 bytes each
        NvData::BooleanArray(v) => {
            flat(out, v, |b| (b as i32).to_le_bytes());
            (DT_BOOLEAN_ARRAY, v.len())
        }
        NvData::StrArray(v) => {
            // nelem 8-byte pointer placeholders, then packed NUL-terminated strings
            out.resize(out.len() + v.len() * 8, 0);
            for s in v {
                out.extend_from_slice(s.as_bytes());
                out.push(0);
            }
            (DT_STRING_ARRAY, v.len())
        }
        NvData::List(l) => {
            write_nvlist_struct(out, l.version, l.nvflag);
            (DT_NVLIST, 1)
        }
        NvData::ListArray(a) => {
            // nelem pointer placeholders, then nelem nvlist_t struct copies;
            // each child's pair stream is appended after the blob by encode_pair.
            let n = a.len();
            out.resize(out.len() + n * 8, 0);
            for l in a {
                write_nvlist_struct(out, l.version, l.nvflag);
            }
            (DT_NVLIST_ARRAY, n)
        }
        // Best-effort: round-trips type+bytes but not the original nvp_value_elem.
        NvData::Unknown { dtype, raw } => {
            out.extend_from_slice(raw);
            (*dtype, 0)
        }
    }
}

/// Write a 24-byte in-memory `nvlist_t` copy as it appears in an embedded value
/// region; only the leading version/nvflag words are meaningful on the wire.
fn write_nvlist_struct(out: &mut Vec<u8>, version: i32, nvflag: u32) {
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&nvflag.to_le_bytes());
    out.resize(out.len() + (NVLIST_STRUCT_SIZE - 8), 0);
}

/* ------------------------------ XDR decoding ----------------------------- */

/*
Format per the comment above `nvs_xdr_create` in doc/reference/nvpair.c:
every list (root and embedded alike) is `i32 version, u32 nvflag`, then
nvpairs, then an 8-byte double-zero terminator. Each nvpair is:
`i32 encoded_size, i32 decoded_size, name (xdr string), i32 type,
i32 nelem, value`. Scalars ≤32 bits occupy 4 bytes, 64-bit ones 8.
Scalar arrays (xdr_array) repeat the element count in a leading u32;
byte arrays (xdr_opaque) and string arrays do not.
*/

/// Decode one XDR nvlist starting at version/nvflag, consuming its terminator.
fn decode_xdr_list(cur: &mut Cursor, depth: usize) -> Result<NvList> {
    if depth > MAX_DEPTH {
        return Err(NvError::TooDeep);
    }
    let version = cur.read_i32_be()?;
    check_version(version)?;
    let nvflag = cur.read_u32_be()?;
    let mut pairs = Vec::new();
    loop {
        let pair_start = cur.pos;
        let encode_sz = cur.read_i32_be()?;
        let decode_sz = cur.read_i32_be()?;
        if encode_sz == 0 && decode_sz == 0 {
            return Ok(NvList { version, nvflag, pairs });
        }
        // encoded size covers the whole pair, the two size words included;
        // note that nvs_xdr_nvp_size over-counts empty number arrays by 4 bytes
        // per array (which also inflates enclosing DT_NVLIST encode_sz), so
        // encode_sz is checked as an upper bound after decoding known types.
        if encode_sz < 20 || decode_sz <= 0 {
            return Err(NvError::BadPairSize { at: pair_start, size: encode_sz as i64 });
        }
        let name = cur.read_xdr_string()?;
        let dtype = cur.read_i32_be()?;
        let nelem = cur.read_i32_be()?;
        if nelem < 0 {
            return Err(NvError::BadArrayCount(nelem as i64));
        }
        let data = decode_xdr_value(cur, dtype, nelem as usize, pair_start, encode_sz, depth)?;
        /*
        Each nvpair is self-describing; a known value's decode must not overrun
        its declared encode_sz. Do not advance `cur.pos` to `pair_end`: every
        XDR primitive already pads to 4 bytes, and `nvs_xdr_nvp_size` adds 4
        bytes for the `xdr_array` count word even when `nelem == 0` causes
        `nvs_xdr_nvp_op` to skip `xdr_array` entirely.
        */
        let pair_end = pair_start.saturating_add(encode_sz as usize);
        if cur.pos > pair_end {
            return Err(NvError::BadPairSize { at: pair_start, size: encode_sz as i64 });
        }
        pairs.push(NvPair { name, data });
    }
}

fn decode_xdr_value(
    cur: &mut Cursor,
    dtype: i32,
    nelem: usize,
    pair_start: usize,
    encode_sz: i32,
    depth: usize,
) -> Result<NvData> {
    /*
    xdr_array repeats the element count on the wire; it is authoritative
    for stream framing and must agree with the declared nelem (count > nelem
    would under-read and desync the following pairs; count < nelem would
    silently drop elements). Require equality, then bound it.
    When nelem == 0, `nvs_xdr_nvp_op` returns before calling `xdr_array`, so
    there is no count word on the wire (`doc/reference/nvpair.c:3337-3339`).
    */
    fn array_count(cur: &mut Cursor, nelem: usize, elem_sz: usize) -> Result<usize> {
        if nelem == 0 {
            return Ok(0);
        }
        let count = cur.read_u32_be()? as usize;
        if count != nelem {
            return Err(NvError::ArrayCountMismatch { count, nelem });
        }
        let need = count.checked_mul(elem_sz).ok_or(NvError::Overflow(count))?;
        if need > cur.remaining() {
            return Err(NvError::Truncated { at: cur.pos, need, have: cur.remaining() });
        }
        Ok(count)
    }

    Ok(match dtype {
        DT_BOOLEAN => NvData::BooleanFlag,
        DT_BOOLEAN_VALUE => NvData::Boolean(cur.read_i32_be()? != 0),
        // sub-32-bit scalars are stretched to the 4-byte XDR unit
        DT_BYTE => NvData::Byte(cur.read_i32_be()? as u8),
        DT_INT8 => NvData::Int8(cur.read_i32_be()? as i8),
        DT_UINT8 => NvData::Uint8(cur.read_i32_be()? as u8),
        DT_INT16 => NvData::Int16(cur.read_i32_be()? as i16),
        DT_UINT16 => NvData::Uint16(cur.read_i32_be()? as u16),
        DT_INT32 => NvData::Int32(cur.read_i32_be()?),
        DT_UINT32 => NvData::Uint32(cur.read_u32_be()?),
        DT_INT64 => NvData::Int64(cur.read_u64_be()? as i64),
        DT_UINT64 => NvData::Uint64(cur.read_u64_be()?),
        DT_HRTIME => NvData::HrTime(cur.read_u64_be()? as i64),
        DT_DOUBLE => NvData::Double(f64::from_bits(cur.read_u64_be()?)),
        DT_STRING => NvData::Str(cur.read_xdr_string()?),
        // xdr_opaque: raw bytes padded to 4, no repeated count
        DT_BYTE_ARRAY => {
            let bytes = cur.take(nelem)?.to_vec();
            cur.take(xdr_pad(nelem))?;
            NvData::ByteArray(bytes)
        }
        DT_INT8_ARRAY => {
            let n = array_count(cur, nelem, 4)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(cur.read_i32_be()? as i8);
            }
            NvData::Int8Array(v)
        }
        DT_UINT8_ARRAY => {
            let n = array_count(cur, nelem, 4)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(cur.read_i32_be()? as u8);
            }
            NvData::Uint8Array(v)
        }
        DT_INT16_ARRAY => {
            let n = array_count(cur, nelem, 4)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(cur.read_i32_be()? as i16);
            }
            NvData::Int16Array(v)
        }
        DT_UINT16_ARRAY => {
            let n = array_count(cur, nelem, 4)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(cur.read_i32_be()? as u16);
            }
            NvData::Uint16Array(v)
        }
        DT_INT32_ARRAY => {
            let n = array_count(cur, nelem, 4)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(cur.read_i32_be()?);
            }
            NvData::Int32Array(v)
        }
        DT_UINT32_ARRAY => {
            let n = array_count(cur, nelem, 4)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(cur.read_u32_be()?);
            }
            NvData::Uint32Array(v)
        }
        DT_BOOLEAN_ARRAY => {
            let n = array_count(cur, nelem, 4)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(cur.read_i32_be()? != 0);
            }
            NvData::BooleanArray(v)
        }
        DT_INT64_ARRAY => {
            let n = array_count(cur, nelem, 8)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(cur.read_u64_be()? as i64);
            }
            NvData::Int64Array(v)
        }
        DT_UINT64_ARRAY => {
            let n = array_count(cur, nelem, 8)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(cur.read_u64_be()?);
            }
            NvData::Uint64Array(v)
        }
        DT_STRING_ARRAY => {
            let mut v = Vec::with_capacity(nelem.min(cur.remaining() / 4));
            for _ in 0..nelem {
                v.push(cur.read_xdr_string()?);
            }
            NvData::StrArray(v)
        }
        DT_NVLIST => NvData::List(decode_xdr_list(cur, depth + 1)?),
        DT_NVLIST_ARRAY => {
            let mut v = Vec::with_capacity(nelem.min(cur.remaining() / 16));
            for _ in 0..nelem {
                v.push(decode_xdr_list(cur, depth + 1)?);
            }
            NvData::ListArray(v)
        }
        _ => {
            // skip to the end of the pair using its encoded size
            let end = pair_start
                .checked_add(encode_sz as usize)
                .filter(|&end| cur.pos <= end && end <= cur.buf.len())
                .ok_or(NvError::BadPairSize { at: pair_start, size: encode_sz as i64 })?;
            let raw = cur.buf[cur.pos..end].to_vec();
            cur.pos = end;
            NvData::Unknown { dtype, raw }
        }
    })
}

impl NvData {
    pub fn type_name(&self) -> &'static str {
        match self {
            NvData::BooleanFlag => "boolean (flag)",
            NvData::Boolean(_) => "boolean",
            NvData::Byte(_) => "byte",
            NvData::Int8(_) => "int8",
            NvData::Uint8(_) => "uint8",
            NvData::Int16(_) => "int16",
            NvData::Uint16(_) => "uint16",
            NvData::Int32(_) => "int32",
            NvData::Uint32(_) => "uint32",
            NvData::Int64(_) => "int64",
            NvData::Uint64(_) => "uint64",
            NvData::HrTime(_) => "hrtime",
            NvData::Double(_) => "double",
            NvData::Str(_) => "string",
            NvData::ByteArray(_) => "byte[]",
            NvData::Int8Array(_) => "int8[]",
            NvData::Uint8Array(_) => "uint8[]",
            NvData::Int16Array(_) => "int16[]",
            NvData::Uint16Array(_) => "uint16[]",
            NvData::Int32Array(_) => "int32[]",
            NvData::Uint32Array(_) => "uint32[]",
            NvData::Int64Array(_) => "int64[]",
            NvData::Uint64Array(_) => "uint64[]",
            NvData::BooleanArray(_) => "boolean[]",
            NvData::StrArray(_) => "string[]",
            NvData::List(_) => "nvlist",
            NvData::ListArray(_) => "nvlist[]",
            NvData::Unknown { .. } => "unknown",
        }
    }
}

/* ========================================================================= */

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only encoder producing the same native format the kernel emits.
    struct Enc {
        buf: Vec<u8>,
    }

    impl Enc {
        fn new() -> Self {
            let mut buf = vec![0u8, 1, 0, 0]; // native, little-endian
            buf.extend_from_slice(&0i32.to_le_bytes()); // nvl_version
            buf.extend_from_slice(&NV_UNIQUE_NAME.to_le_bytes()); // nvl_nvflag
            Enc { buf }
        }

        /**
        Emit an nvpair blob. `value` is the raw value region (already in
        wire form); stream-trailing data (embedded lists) is appended by
        the caller afterwards.
        */
        fn pair(&mut self, name: &str, dtype: i32, nelem: i32, value: &[u8]) {
            let name_sz = name.len() + 1;
            let val_off = align8(NVPAIR_HDR_SIZE + name_sz);
            let size = val_off + align8(value.len());
            self.buf.extend_from_slice(&(size as i32).to_le_bytes());
            self.buf.extend_from_slice(&(name_sz as i16).to_le_bytes());
            self.buf.extend_from_slice(&0i16.to_le_bytes());
            self.buf.extend_from_slice(&nelem.to_le_bytes());
            self.buf.extend_from_slice(&dtype.to_le_bytes());
            self.buf.extend_from_slice(name.as_bytes());
            self.buf.push(0);
            self.buf
                .resize(self.buf.len() + (val_off - NVPAIR_HDR_SIZE - name_sz), 0);
            self.buf.extend_from_slice(value);
            self.buf
                .resize(self.buf.len() + (align8(value.len()) - value.len()), 0);
        }

        fn end(&mut self) {
            self.buf.extend_from_slice(&0i32.to_le_bytes());
        }
    }

    #[test]
    fn empty_list() {
        let mut e = Enc::new();
        e.end();
        let l = NvList::unpack(&e.buf).unwrap();
        assert_eq!(l.version, 0);
        assert_eq!(l.nvflag, NV_UNIQUE_NAME);
        assert!(l.pairs.is_empty());
    }

    #[test]
    fn scalars_and_strings() {
        let mut e = Enc::new();
        e.pair("guid", DT_UINT64, 1, &0x1122334455667788u64.to_le_bytes());
        e.pair("name", DT_STRING, 1, b"tank\0");
        e.pair("flag", DT_BOOLEAN, 0, &[]);
        e.pair("ok", DT_BOOLEAN_VALUE, 1, &1i32.to_le_bytes());
        e.end();
        let l = NvList::unpack(&e.buf).unwrap();
        assert_eq!(l.get_u64("guid"), Some(0x1122334455667788));
        assert_eq!(l.get_str("name"), Some("tank"));
        assert_eq!(l.get("flag"), Some(&NvData::BooleanFlag));
        assert_eq!(l.get("ok"), Some(&NvData::Boolean(true)));
        assert_eq!(l.pairs.len(), 4);
    }

    #[test]
    fn scalar_arrays() {
        let mut e = Enc::new();
        let vals: Vec<u8> = [1u64, 2, 3].iter().flat_map(|v| v.to_le_bytes()).collect();
        e.pair("nums", DT_UINT64_ARRAY, 3, &vals);
        e.end();
        let l = NvList::unpack(&e.buf).unwrap();
        assert_eq!(l.get_u64_array("nums"), Some(&[1u64, 2, 3][..]));
    }

    #[test]
    fn string_array() {
        let mut e = Enc::new();
        let mut val = vec![0u8; 2 * 8]; // pointer placeholders
        val.extend_from_slice(b"a\0bc\0");
        e.pair("strs", DT_STRING_ARRAY, 2, &val);
        e.end();
        let l = NvList::unpack(&e.buf).unwrap();
        assert_eq!(
            l.get("strs"),
            Some(&NvData::StrArray(vec!["a".into(), "bc".into()]))
        );
    }

    #[test]
    fn embedded_nvlist() {
        let mut e = Enc::new();
        // parent pair: value is a 24-byte nvlist_t copy
        let mut nvl_struct = [0u8; NVLIST_STRUCT_SIZE];
        nvl_struct[4..8].copy_from_slice(&NV_UNIQUE_NAME.to_le_bytes());
        e.pair("child", DT_NVLIST, 1, &nvl_struct);
        // child's pairs follow in the stream
        e.pair("answer", DT_UINT64, 1, &42u64.to_le_bytes());
        e.end(); // terminates child
        e.pair("after", DT_UINT64, 1, &7u64.to_le_bytes());
        e.end(); // terminates root
        let l = NvList::unpack(&e.buf).unwrap();
        let child = l.get_list("child").unwrap();
        assert_eq!(child.get_u64("answer"), Some(42));
        assert_eq!(child.nvflag, NV_UNIQUE_NAME);
        assert_eq!(l.get_u64("after"), Some(7));
    }

    #[test]
    fn nvlist_array() {
        let mut e = Enc::new();
        let nelem = 2;
        let mut val = vec![0u8; nelem * 8];
        val.resize(nelem * 8 + nelem * NVLIST_STRUCT_SIZE, 0);
        e.pair("vdevs", DT_NVLIST_ARRAY, nelem as i32, &val);
        // two child streams follow, each zero-terminated
        e.pair("id", DT_UINT64, 1, &0u64.to_le_bytes());
        e.end();
        e.pair("id", DT_UINT64, 1, &1u64.to_le_bytes());
        e.end();
        e.end(); // root
        let l = NvList::unpack(&e.buf).unwrap();
        let arr = l.get_list_array("vdevs").unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].get_u64("id"), Some(0));
        assert_eq!(arr[1].get_u64("id"), Some(1));
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        let mut e = Enc::new();
        e.pair("guid", DT_UINT64, 1, &1u64.to_le_bytes());
        e.end();
        for cut in 0..e.buf.len() - 1 {
            assert!(NvList::unpack(&e.buf[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn garbage_pair_size_rejected() {
        let mut e = Enc::new();
        e.buf.extend_from_slice(&(-5i32).to_le_bytes());
        assert!(NvList::unpack(&e.buf).is_err());
    }

    #[test]
    fn native_negative_nelem_rejected() {
        let mut e = Enc::new();
        e.pair("arr", DT_UINT64_ARRAY, -1, &[0u8; 8]);
        e.end();
        assert!(NvList::unpack(&e.buf).is_err());
    }

    #[test]
    fn native_unterminated_name_rejected() {
        let mut e = Enc::new();
        e.pair("ab", DT_UINT64, 1, &0u64.to_le_bytes());
        e.end();
        assert!(NvList::unpack(&e.buf).is_ok());
        // corrupt the name's trailing NUL: "ab\0" begins after the 12-byte
        // stream header (encoding+version+nvflag) plus the 16-byte pair header
        e.buf[12 + NVPAIR_HDR_SIZE + 2] = b'!';
        assert!(NvList::unpack(&e.buf).is_err());
    }

    /* ----------------------------- encode (pack) ------------------------- */

    /**
    The production `pack()` must be byte-identical to the reference `Enc`
    for the same pairs in the same order (both emit the kernel's native
    format with version 0 / NV_UNIQUE_NAME).
    */
    #[test]
    fn pack_matches_reference_encoder() {
        let mut e = Enc::new();
        e.pair("guid", DT_UINT64, 1, &0x1122334455667788u64.to_le_bytes());
        e.pair("name", DT_STRING, 1, b"tank\0");
        e.pair("flag", DT_BOOLEAN, 0, &[]);
        e.pair("ok", DT_BOOLEAN_VALUE, 1, &1i32.to_le_bytes());
        e.end();

        let mut l = NvList::new();
        l.add_u64("guid", 0x1122334455667788)
            .add_str("name", "tank")
            .add_bool_flag("flag")
            .add_boolean("ok", true);

        assert_eq!(l.pack().unwrap(), e.buf);
    }

    /// pack → unpack is the identity for every value variant writes can use.
    #[test]
    fn pack_unpack_round_trip() {
        let mut child = NvList::new();
        child.add_u64("answer", 42).add_str("who", "deep thought");

        let mut grandchild_a = NvList::new();
        grandchild_a.add_u64("id", 0);
        let mut grandchild_b = NvList::new();
        grandchild_b.add_u64("id", 1).add_bool_flag("is_log");

        let mut l = NvList::new();
        l.push("u64", NvData::Uint64(0xdead_beef_cafe_f00d))
            .push("i32", NvData::Int32(-7))
            .push("u16", NvData::Uint16(12))
            .push("byte", NvData::Byte(0xab))
            .push("bool", NvData::Boolean(false))
            .push("flag", NvData::BooleanFlag)
            .push("hrt", NvData::HrTime(-123))
            .push("dbl", NvData::Double(3.5))
            .add_str("str", "hello")
            .push("bytes", NvData::ByteArray(vec![1, 2, 3, 4, 5]))
            .push("u64s", NvData::Uint64Array(vec![1, 2, 3]))
            .push("i16s", NvData::Int16Array(vec![-1, 0, 1]))
            .push("bools", NvData::BooleanArray(vec![true, false, true]))
            .add_str_array("strs", vec!["a".into(), "bc".into(), "".into()])
            .add_nvlist("child", child)
            .push("vdevs", NvData::ListArray(vec![grandchild_a, grandchild_b]));

        let packed = l.pack().unwrap();
        let back = NvList::unpack(&packed).unwrap();
        assert_eq!(back, l);
    }

    #[test]
    fn pack_empty_round_trip() {
        let l = NvList::new();
        let back = NvList::unpack(&l.pack().unwrap()).unwrap();
        assert_eq!(back, l);
        assert!(back.pairs.is_empty());
        assert_eq!(back.nvflag, NV_UNIQUE_NAME);
    }

    /// A nested-empty list still produces a parseable stream (the embedded
    /// child reduces to a lone terminator after its parent blob).
    #[test]
    fn pack_nested_empty_round_trip() {
        let mut l = NvList::new();
        l.add_nvlist("snaps", NvList::new());
        let back = NvList::unpack(&l.pack().unwrap()).unwrap();
        assert_eq!(back, l);
        assert!(back.get_list("snaps").unwrap().pairs.is_empty());
    }

    /// Interior NULs would silently re-frame on the kernel side (its
    /// validator recomputes strlen); pack must refuse them.
    #[test]
    fn pack_rejects_embedded_nul() {
        let mut l = NvList::new();
        l.add_str("prop", "a\0b");
        assert!(matches!(l.pack(), Err(NvError::EmbeddedNul(_))));

        let mut l2 = NvList::new();
        l2.push("na\0me", NvData::Uint64(1));
        assert!(matches!(l2.pack(), Err(NvError::EmbeddedNul(_))));

        let mut l3 = NvList::new();
        l3.add_str_array("strs", vec!["ok".into(), "b\0ad".into()]);
        assert!(matches!(l3.pack(), Err(NvError::EmbeddedNul(_))));
    }

    /// An oversized name must error, not wrap the i16 nvp_name_sz cast.
    #[test]
    fn pack_rejects_oversized_name() {
        let mut l = NvList::new();
        l.push("x".repeat(40_000), NvData::Uint64(1));
        assert!(matches!(l.pack(), Err(NvError::TooBigToPack(_))));
    }

    /// Duplicate names resolve to the LAST occurrence, like the kernel's
    /// NV_UNIQUE_NAME decode (nvt_add_nvpair unlinks the earlier one).
    #[test]
    fn duplicate_names_resolve_to_last() {
        let mut e = Enc::new();
        e.pair("guid", DT_UINT64, 1, &1u64.to_le_bytes());
        e.pair("guid", DT_UINT64, 1, &2u64.to_le_bytes());
        e.end();
        let l = NvList::unpack(&e.buf).unwrap();
        assert_eq!(l.get_u64("guid"), Some(2));
    }

    /* ------------------------------- XDR tests --------------------------- */

    /// Test-only XDR encoder mirroring nvs_xdr_* output.
    struct XdrEnc {
        buf: Vec<u8>,
    }

    impl XdrEnc {
        fn new() -> Self {
            let mut buf = vec![1u8, 1, 0, 0]; // xdr encoding, LE host marker
            buf.extend_from_slice(&0i32.to_be_bytes());
            buf.extend_from_slice(&NV_UNIQUE_NAME.to_be_bytes());
            XdrEnc { buf }
        }

        fn xdr_str(out: &mut Vec<u8>, s: &str) {
            out.extend_from_slice(&(s.len() as u32).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
            out.resize(out.len() + xdr_pad(s.len()), 0);
        }

        /// Emit one nvpair. `value` is already in XDR wire form.
        fn pair(&mut self, name: &str, dtype: i32, nelem: i32, value: &[u8]) {
            let mut body = Vec::new();
            Self::xdr_str(&mut body, name);
            body.extend_from_slice(&dtype.to_be_bytes());
            body.extend_from_slice(&nelem.to_be_bytes());
            body.extend_from_slice(value);
            // encode size covers the two size words + body
            self.buf.extend_from_slice(&((body.len() + 8) as i32).to_be_bytes());
            // decode size: in-memory estimate, only sanity-checked
            self.buf.extend_from_slice(&64i32.to_be_bytes());
            self.buf.extend_from_slice(&body);
        }

        fn end(&mut self) {
            self.buf.extend_from_slice(&[0u8; 8]);
        }
    }

    #[test]
    fn xdr_scalars() {
        let mut e = XdrEnc::new();
        e.pair("guid", DT_UINT64, 1, &0xdeadbeefcafef00du64.to_be_bytes());
        let mut sval = Vec::new();
        XdrEnc::xdr_str(&mut sval, "tank");
        e.pair("name", DT_STRING, 1, &sval);
        e.pair("flag", DT_BOOLEAN, 0, &[]);
        e.pair("ashift", DT_UINT16, 1, &12i32.to_be_bytes()); // stretched to 4B
        e.end();
        let l = NvList::unpack(&e.buf).unwrap();
        assert_eq!(l.nvflag, NV_UNIQUE_NAME);
        assert_eq!(l.get_u64("guid"), Some(0xdeadbeefcafef00d));
        assert_eq!(l.get_str("name"), Some("tank"));
        assert_eq!(l.get("flag"), Some(&NvData::BooleanFlag));
        assert_eq!(l.get("ashift"), Some(&NvData::Uint16(12)));
    }

    #[test]
    fn xdr_arrays() {
        let mut e = XdrEnc::new();
        // u64 array: repeated count + 8-byte elements
        let mut v = 3u32.to_be_bytes().to_vec();
        for x in [1u64, 2, 3] {
            v.extend_from_slice(&x.to_be_bytes());
        }
        e.pair("nums", DT_UINT64_ARRAY, 3, &v);
        // u16 array: repeated count + 4-byte elements
        let mut v = 2u32.to_be_bytes().to_vec();
        v.extend_from_slice(&7i32.to_be_bytes());
        v.extend_from_slice(&9i32.to_be_bytes());
        e.pair("shorts", DT_UINT16_ARRAY, 2, &v);
        // byte array: opaque, padded, no repeated count
        e.pair("blob", DT_BYTE_ARRAY, 5, &[1, 2, 3, 4, 5, 0, 0, 0]);
        // string array: strings only, no repeated count
        let mut v = Vec::new();
        XdrEnc::xdr_str(&mut v, "a");
        XdrEnc::xdr_str(&mut v, "bc");
        e.pair("strs", DT_STRING_ARRAY, 2, &v);
        e.end();
        let l = NvList::unpack(&e.buf).unwrap();
        assert_eq!(l.get_u64_array("nums"), Some(&[1u64, 2, 3][..]));
        assert_eq!(l.get("shorts"), Some(&NvData::Uint16Array(vec![7, 9])));
        assert_eq!(l.get("blob"), Some(&NvData::ByteArray(vec![1, 2, 3, 4, 5])));
        assert_eq!(
            l.get("strs"),
            Some(&NvData::StrArray(vec!["a".into(), "bc".into()]))
        );
    }

    #[test]
    fn xdr_embedded_lists() {
        let mut e = XdrEnc::new();
        // embedded nvlist: full list (version+nvflag+pairs+terminator) inline
        let mut child = Vec::new();
        child.extend_from_slice(&0i32.to_be_bytes());
        child.extend_from_slice(&NV_UNIQUE_NAME.to_be_bytes());
        {
            let mut inner = XdrEnc { buf: Vec::new() };
            inner.pair("answer", DT_UINT64, 1, &42u64.to_be_bytes());
            inner.end();
            child.extend_from_slice(&inner.buf);
        }
        e.pair("child", DT_NVLIST, 1, &child);
        // nvlist array: two full lists back to back
        let mut arr = Vec::new();
        for id in [0u64, 1] {
            arr.extend_from_slice(&0i32.to_be_bytes());
            arr.extend_from_slice(&NV_UNIQUE_NAME.to_be_bytes());
            let mut inner = XdrEnc { buf: Vec::new() };
            inner.pair("id", DT_UINT64, 1, &id.to_be_bytes());
            inner.end();
            arr.extend_from_slice(&inner.buf);
        }
        e.pair("vdevs", DT_NVLIST_ARRAY, 2, &arr);
        e.end();
        let l = NvList::unpack(&e.buf).unwrap();
        assert_eq!(l.get_list("child").unwrap().get_u64("answer"), Some(42));
        let vdevs = l.get_list_array("vdevs").unwrap();
        assert_eq!(vdevs.len(), 2);
        assert_eq!(vdevs[1].get_u64("id"), Some(1));
    }

    #[test]
    fn xdr_array_count_mismatch_rejected() {
        // declare nelem = 2 but write a wire count of 3 — a contradiction
        // that previously under-read (min) and desynced the stream
        let mut e = XdrEnc::new();
        let mut v = 3u32.to_be_bytes().to_vec();
        for x in [1u64, 2, 3] {
            v.extend_from_slice(&x.to_be_bytes());
        }
        e.pair("nums", DT_UINT64_ARRAY, 2, &v);
        e.end();
        assert!(NvList::unpack(&e.buf).is_err());
    }

    #[test]
    fn xdr_truncation_is_an_error_not_a_panic() {
        let mut e = XdrEnc::new();
        e.pair("guid", DT_UINT64, 1, &1u64.to_be_bytes());
        let mut sval = Vec::new();
        XdrEnc::xdr_str(&mut sval, "tank");
        e.pair("name", DT_STRING, 1, &sval);
        e.end();
        for cut in 0..e.buf.len() - 1 {
            assert!(NvList::unpack(&e.buf[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn xdr_empty_number_arrays_and_nested_lists() {
        // Match nvs_xdr_nvp_size: every empty numeric array has encode_sz
        // four bytes larger than its actual stream, with no count word.
        let mut inner = XdrEnc { buf: Vec::new() };
        for (name, dtype) in [("e1", DT_UINT64_ARRAY), ("e2", DT_INT32_ARRAY), ("e3", DT_UINT16_ARRAY)] {
            let start = inner.buf.len();
            inner.pair(name, dtype, 0, &[]);
            let encode_sz = (inner.buf.len() - start + 4) as i32;
            inner.buf[start..start + 4].copy_from_slice(&encode_sz.to_be_bytes());
            // The native decode size is NV_ALIGN(16 + name_sz), no value.
            inner.buf[start + 4..start + 8].copy_from_slice(&24i32.to_be_bytes());
        }
        let start = inner.buf.len();
        inner.pair("after_empty", DT_UINT64, 1, &99u64.to_be_bytes());
        inner.buf[start + 4..start + 8].copy_from_slice(&40i32.to_be_bytes());
        inner.end();

        let mut child_payload = Vec::new();
        child_payload.extend_from_slice(&0i32.to_be_bytes());
        child_payload.extend_from_slice(&NV_UNIQUE_NAME.to_be_bytes());
        child_payload.extend_from_slice(&inner.buf);

        for dtype in [DT_NVLIST, DT_NVLIST_ARRAY] {
            for with_tail in [false, true] {
                let mut e = XdrEnc::new();
                let start = e.buf.len();
                e.pair("child", dtype, 1, &child_payload);
                // Enclosing sizes also include each child's phantom count.
                let encode_sz = (e.buf.len() - start + 12) as i32;
                let decode_sz: i32 = if dtype == DT_NVLIST { 48 } else { 56 };
                e.buf[start..start + 4].copy_from_slice(&encode_sz.to_be_bytes());
                e.buf[start + 4..start + 8].copy_from_slice(&decode_sz.to_be_bytes());
                if with_tail {
                    let start = e.buf.len();
                    e.pair("tail", DT_UINT64, 1, &7u64.to_be_bytes());
                    e.buf[start + 4..start + 8].copy_from_slice(&32i32.to_be_bytes());
                }
                // Without a tail, the +12 exceeds the old +8 allowance.
                e.end();

                let l = NvList::unpack(&e.buf).unwrap();
                let child = if dtype == DT_NVLIST {
                    l.get_list("child").unwrap()
                } else {
                    &l.get_list_array("child").unwrap()[0]
                };
                assert_eq!(child.get_u64_array("e1"), Some(&[][..]));
                assert_eq!(child.get("e2"), Some(&NvData::Int32Array(vec![])));
                assert_eq!(child.get("e3"), Some(&NvData::Uint16Array(vec![])));
                assert_eq!(child.get_u64("after_empty"), Some(99));
                assert_eq!(l.get_u64("tail"), with_tail.then_some(7));
            }
        }
    }

    #[test]
    fn unpack_rejects_embedded_nul_in_names_and_xdr_strings() {
        // Native pair name with interior NUL
        let mut e = Enc::new();
        e.pair("a\0b", DT_UINT64, 1, &1u64.to_le_bytes());
        e.end();
        assert!(matches!(NvList::unpack(&e.buf), Err(NvError::BadName { .. })));

        // XDR string with interior NUL
        let mut xe = XdrEnc::new();
        let mut sval = Vec::new();
        XdrEnc::xdr_str(&mut sval, "a\0b");
        xe.pair("prop", DT_STRING, 1, &sval);
        xe.end();
        assert!(matches!(NvList::unpack(&xe.buf), Err(NvError::EmbeddedNul(_))));
    }

    #[test]
    fn push_deduplicates_when_nv_unique_name_set() {
        let mut unique = NvList::new();
        unique.add_u64("k", 1).add_u64("other", 2).add_u64("k", 3);
        assert_eq!(unique.pairs.len(), 2);
        assert_eq!(unique.pairs[0].name, "other");
        assert_eq!(unique.pairs[1].name, "k");
        assert_eq!(unique.get_u64("k"), Some(3));

        // Lists with nvflag == 0 keep duplicate keys
        let mut non_unique = NvList { version: 0, nvflag: 0, pairs: Vec::new() };
        non_unique.add_u64("k", 1).add_u64("k", 2);
        assert_eq!(non_unique.pairs.len(), 2);
        assert_eq!(non_unique.get_u64("k"), Some(2));

        // Default nvlist has NV_UNIQUE_NAME
        assert_eq!(NvList::default().nvflag, NV_UNIQUE_NAME);
    }

    #[test]
    fn pack_rejects_excessive_nesting_depth() {
        let mut list = NvList::new();
        for _ in 0..=MAX_DEPTH {
            let mut parent = NvList::new();
            parent.add_nvlist("child", list);
            list = parent;
        }
        assert!(matches!(list.pack(), Err(NvError::TooDeep)));
    }

    #[test]
    fn unsupported_versions_are_rejected_in_roots_and_embedded_lists() {
        let invalid = NvList { version: 1, ..NvList::new() };
        assert!(matches!(invalid.pack(), Err(NvError::UnsupportedVersion(1))));
        for data in [NvData::List(invalid.clone()), NvData::ListArray(vec![invalid])] {
            let mut root = NvList::new();
            root.push("child", data);
            assert!(matches!(root.pack(), Err(NvError::UnsupportedVersion(1))));
        }
        let mut native = NvList::new().pack().unwrap();
        native[4..8].copy_from_slice(&1i32.to_le_bytes());
        assert!(matches!(NvList::unpack(&native), Err(NvError::UnsupportedVersion(1))));
        for dtype in [DT_NVLIST, DT_NVLIST_ARRAY] {
            let mut e = Enc::new();
            let mut hdr = Vec::new();
            if dtype == DT_NVLIST_ARRAY {
                hdr.extend_from_slice(&[0; 8]);
            }
            write_nvlist_struct(&mut hdr, 1, NV_UNIQUE_NAME);
            e.pair("child", dtype, 1, &hdr);
            e.end(); // child terminator
            e.end(); // root terminator
            assert!(matches!(NvList::unpack(&e.buf), Err(NvError::UnsupportedVersion(1))));

            let mut xdr = XdrEnc::new();
            let mut child = XdrEnc::new().buf[4..].to_vec();
            child[..4].copy_from_slice(&1i32.to_be_bytes());
            child.extend_from_slice(&[0; 8]);
            xdr.pair("child", dtype, 1, &child);
            xdr.end();
            assert!(matches!(NvList::unpack(&xdr.buf), Err(NvError::UnsupportedVersion(1))));
        }
        let mut xdr = XdrEnc::new();
        xdr.end();
        xdr.buf[4..8].copy_from_slice(&1i32.to_be_bytes());
        assert!(matches!(NvList::unpack(&xdr.buf), Err(NvError::UnsupportedVersion(1))));
    }
}
