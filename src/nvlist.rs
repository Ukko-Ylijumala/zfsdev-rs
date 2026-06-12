// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Pure-Rust decoder for packed Solaris/OpenZFS name-value lists (nvlists).

This implements the "native" encoding used by the `/dev/zfs` ioctl
interface. The format is defined by `nvs_native_*` in
`doc/reference/nvpair.c` (vendored from OpenZFS 2.2.2):

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
    #[error("unsupported nvlist encoding {0} (only native supported)")]
    UnsupportedEncoding(u8),
    #[error("unsupported endianness {0}")]
    UnsupportedEndian(u8),
    #[error("invalid nvpair size {size} at offset {at}")]
    BadPairSize { at: usize, size: i64 },
    #[error("invalid nvpair name (name_sz {0})")]
    BadName(i16),
    #[error("string value not NUL-terminated in pair '{0}'")]
    BadString(String),
    #[rustfmt::skip]
    #[error("value for '{name}' ({need} bytes) exceeds nvpair bounds ({have} bytes)")]
    ValueOverflow { name: String, need: usize, have: usize },
    #[error("nvlist nesting deeper than {MAX_DEPTH}")]
    TooDeep,
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

#[derive(Debug, Clone, Default, PartialEq)]
pub struct NvList {
    pub version: i32,
    pub nvflag: u32,
    pub pairs: Vec<NvPair>,
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
}

impl NvList {
    /// Decode a packed nvlist (with stream header) in native encoding.
    #[rustfmt::skip]
    pub fn unpack(buf: &[u8]) -> Result<NvList> {
        let mut cur = Cursor { buf, pos: 0 };
        let hdr = cur.take(4)?;
        match hdr[0] {
            0 => (),
            other => return Err(NvError::UnsupportedEncoding(other)),
        }
        // nvs_header_t.nvh_endian: 1 = little. Big-endian streams only occur
        // on big-endian hosts, which we don't target yet.
        if hdr[1] != 1 {
            return Err(NvError::UnsupportedEndian(hdr[1]));
        }
        let version = cur.read_i32()?;
        let nvflag = cur.read_u32()?;
        let pairs = decode_pairs(&mut cur, 0)?;
        Ok(NvList { version, nvflag, pairs })
    }

    pub fn iter(&self) -> impl Iterator<Item = &NvPair> {
        self.pairs.iter()
    }

    pub fn get(&self, name: &str) -> Option<&NvData> {
        self.pairs.iter().find(|p| p.name == name).map(|p| &p.data)
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

        if name_sz < 1 || NVPAIR_HDR_SIZE + name_sz as usize > blob.len() {
            return Err(NvError::BadName(name_sz));
        }
        let name_bytes = &blob[NVPAIR_HDR_SIZE..NVPAIR_HDR_SIZE + name_sz as usize - 1];
        let name = String::from_utf8_lossy(name_bytes).into_owned();

        let val_off = align8(NVPAIR_HDR_SIZE + name_sz as usize);
        let value = blob.get(val_off..).unwrap_or(&[]);
        let nelem = value_elem.max(0) as usize;

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
        value.get(..n).ok_or(NvError::ValueOverflow {
            name: name.to_string(),
            need: n,
            have: value.len(),
        })
    };
    let scalar_array = |elem_sz: usize| -> Result<Vec<&[u8]>> {
        let raw = need(nelem * elem_sz)?;
        Ok(raw.chunks_exact(elem_sz).collect())
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
                .iter()
                .map(|c| i16::from_le_bytes((*c).try_into().unwrap()))
                .collect(),
        ),
        DT_UINT16_ARRAY => NvData::Uint16Array(
            scalar_array(2)?
                .iter()
                .map(|c| u16::from_le_bytes((*c).try_into().unwrap()))
                .collect(),
        ),
        DT_INT32_ARRAY => NvData::Int32Array(
            scalar_array(4)?
                .iter()
                .map(|c| i32::from_le_bytes((*c).try_into().unwrap()))
                .collect(),
        ),
        DT_UINT32_ARRAY => NvData::Uint32Array(
            scalar_array(4)?
                .iter()
                .map(|c| u32::from_le_bytes((*c).try_into().unwrap()))
                .collect(),
        ),
        DT_INT64_ARRAY => NvData::Int64Array(
            scalar_array(8)?
                .iter()
                .map(|c| i64::from_le_bytes((*c).try_into().unwrap()))
                .collect(),
        ),
        DT_UINT64_ARRAY => NvData::Uint64Array(
            scalar_array(8)?
                .iter()
                .map(|c| u64::from_le_bytes((*c).try_into().unwrap()))
                .collect(),
        ),
        // boolean_t array elements are 4 bytes each
        DT_BOOLEAN_ARRAY => NvData::BooleanArray(
            scalar_array(4)?
                .iter()
                .map(|c| i32::from_le_bytes((*c).try_into().unwrap()) != 0)
                .collect(),
        ),
        DT_STRING_ARRAY => {
            // nelem pointer placeholders, then packed NUL-terminated strings
            let mut rest = need(nelem * 8).map(|_| &value[nelem * 8..])?;
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
            let hdrs = need(nelem * 8 + nelem * NVLIST_STRUCT_SIZE)?;
            let mut lists = Vec::with_capacity(nelem);
            for i in 0..nelem {
                let off = nelem * 8 + i * NVLIST_STRUCT_SIZE;
                let version = i32::from_le_bytes(hdrs[off..off + 4].try_into().unwrap());
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

    /// Short single-line rendering for list views.
    pub fn summary(&self) -> String {
        fn arr<T: std::fmt::Display>(v: &[T]) -> String {
            const MAX: usize = 8;
            let shown: Vec<String> = v.iter().take(MAX).map(|x| x.to_string()).collect();
            let ell = if v.len() > MAX { ", …" } else { "" };
            format!("[{}{ell}] ({} elems)", shown.join(", "), v.len())
        }
        match self {
            NvData::BooleanFlag => "(set)".into(),
            NvData::Boolean(b) => b.to_string(),
            NvData::Byte(v) => format!("{v:#04x}"),
            NvData::Int8(v) => v.to_string(),
            NvData::Uint8(v) => v.to_string(),
            NvData::Int16(v) => v.to_string(),
            NvData::Uint16(v) => v.to_string(),
            NvData::Int32(v) => v.to_string(),
            NvData::Uint32(v) => v.to_string(),
            NvData::Int64(v) => v.to_string(),
            NvData::Uint64(v) => v.to_string(),
            NvData::HrTime(v) => format!("{v} ns"),
            NvData::Double(v) => v.to_string(),
            NvData::Str(s) => s.clone(),
            NvData::ByteArray(v) => format!("{} bytes", v.len()),
            NvData::Int8Array(v) => arr(v),
            NvData::Uint8Array(v) => arr(v),
            NvData::Int16Array(v) => arr(v),
            NvData::Uint16Array(v) => arr(v),
            NvData::Int32Array(v) => arr(v),
            NvData::Uint32Array(v) => arr(v),
            NvData::Int64Array(v) => arr(v),
            NvData::Uint64Array(v) => arr(v),
            NvData::BooleanArray(v) => arr(v),
            NvData::StrArray(v) => arr(v),
            NvData::List(l) => format!("nvlist ({} pairs)", l.pairs.len()),
            NvData::ListArray(a) => format!("nvlist[{}]", a.len()),
            NvData::Unknown { dtype, raw } => {
                format!("unknown type {dtype} ({} bytes)", raw.len())
            }
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
}
