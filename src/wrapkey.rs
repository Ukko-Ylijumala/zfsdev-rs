// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Wrapping key derivation for native encryption — libzfs_crypto.c's userspace
half of `zfs load-key`. Whatever the user supplies (a passphrase, a hex
string, raw bytes, per the dataset's `keyformat`) becomes the 32-byte
*wrapping key*; the kernel only ever checks those raw bytes against the
wrapped master key's AEAD MAC (LOAD_KEY: EACCES = wrong key). The same
derivation unlocks an encrypted dataset read straight off disk.
*/

use super::props::KeyFormat;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use thiserror::Error;

/// WRAPPING_KEY_LEN: every ZFS wrapping key is 256 bits regardless of the
/// dataset's encryption suite (aes-128-* still wraps with a 32-byte key).
pub const WRAPPING_KEY_LEN: usize = 32;
/// Digits of a `keyformat=hex` key.
const HEX_KEY_DIGITS: usize = WRAPPING_KEY_LEN * 2;

/**
Sanity cap on `pbkdf2iters`, which is read from the (possibly hostile)
image's DSL Crypto Key ZAP: 2^32-1 iterations would pin the calling thread
for many minutes with no way to cancel. libzfs defaults to
350k (minimum 100k); 100M is ~300x the default and still bounded to tens of
seconds.
*/
const MAX_PBKDF2_ITERS: u64 = 100_000_000;

/// Key material that can't make a wrapping key. No message ever echoes the
/// material itself.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum KeyMaterialError {
    #[error("raw key must be exactly {WRAPPING_KEY_LEN} bytes (got {0})")]
    RawLength(usize),
    #[error("hex key must be exactly {HEX_KEY_DIGITS} hex digits (got {0})")]
    HexLength(usize),
    /// The 1-based digit pair that isn't hex.
    #[error("invalid hex digit in key (pair {0})")]
    HexDigit(usize),
    #[error("pbkdf2iters is 0 — not a passphrase-keyed dataset?")]
    NoIterations,
    #[error("pbkdf2iters {0} exceeds the {MAX_PBKDF2_ITERS} sanity cap (corrupt key object?)")]
    TooManyIterations(u64),
    #[error("dataset is not encrypted")]
    NotEncrypted,
}

/**
Derive the 32-byte wrapping key from user-supplied key `material` per the
dataset's `keyformat`. `salt`/`iters` are the dataset's `pbkdf2salt` /
`pbkdf2iters` properties (passphrase format only — the salt bytes are the
u64's little-endian encoding, matching libzfs's `LE_64(salt)`).
*/
pub fn derive_wrapping_key(
    format: KeyFormat,
    material: &[u8],
    salt: u64,
    iters: u64,
) -> Result<[u8; WRAPPING_KEY_LEN], KeyMaterialError> {
    let mut key = [0u8; WRAPPING_KEY_LEN];
    match format {
        KeyFormat::Raw => {
            if material.len() != WRAPPING_KEY_LEN {
                return Err(KeyMaterialError::RawLength(material.len()));
            }
            key.copy_from_slice(material);
        }
        KeyFormat::Hex => {
            let digits = key_line(material);
            if digits.len() != HEX_KEY_DIGITS {
                return Err(KeyMaterialError::HexLength(digits.len()));
            }
            for (i, pair) in digits.chunks_exact(2).enumerate() {
                let (Some(hi), Some(lo)) = (hex_digit(pair[0]), hex_digit(pair[1])) else {
                    return Err(KeyMaterialError::HexDigit(i + 1));
                };
                key[i] = (hi << 4) | lo;
            }
        }
        KeyFormat::Passphrase => {
            if iters == 0 {
                return Err(KeyMaterialError::NoIterations);
            }
            if iters > MAX_PBKDF2_ITERS {
                return Err(KeyMaterialError::TooManyIterations(iters));
            }
            // PBKDF2 sees strlen(key): the passphrase ends at the first NUL
            let line = key_line(material);
            let pass = &line[..line.iter().position(|&b| b == 0).unwrap_or(line.len())];
            pbkdf2_hmac::<Sha1>(pass, &salt.to_le_bytes(), iters as u32, &mut key);
        }
        KeyFormat::None => return Err(KeyMaterialError::NotEncrypted),
    }
    Ok(key)
}

/**
Passphrase/hex key material exactly as libzfs reads it
(`get_key_material_raw`): the first line only, minus exactly one trailing
`\n` (getline + strip). Anything after the first line is ignored and a `\r`
stays part of the key — a CRLF passphrase file derives from "pass\r" in
`zfs load-key`, so it must here too. Bytes, not text: a passphrase need not
be UTF-8.
*/
fn key_line(material: &[u8]) -> &[u8] {
    match material.iter().position(|&b| b == b'\n') {
        Some(i) => &material[..i],
        None => material,
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/* ================================== tests ================================= */

#[cfg(test)]
mod tests {
    use super::*;

    /*
    KAT generated with `openssl kdf -keylen 32 -kdfopt digest:SHA1 -kdfopt
    pass:testpassphrase -kdfopt hexsalt:efcdab8967452301 -kdfopt iter:350000
    PBKDF2` — hexsalt is the little-endian encoding of the u64 below, exactly
    how libzfs feeds the stored `pbkdf2salt` property to PBKDF2.
    */
    #[test]
    fn passphrase_pbkdf2_matches_openssl() {
        let key = derive_wrapping_key(
            KeyFormat::Passphrase,
            b"testpassphrase",
            0x0123_4567_89ab_cdef,
            350_000,
        )
        .unwrap();
        let expect = "ff69fd8be326347f9203710ec8c11c27ff35eafc2d31cc0ff7669a8f80626cd2";
        let got: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, expect);
    }

    /// libzfs key-file semantics: first line, one trailing `\n` stripped,
    /// `\r` kept, passphrase ends at a NUL, bytes need not be UTF-8.
    #[test]
    fn key_material_follows_libzfs_line_rules() {
        let d = |m: &[u8]| derive_wrapping_key(KeyFormat::Passphrase, m, 1, 1000).unwrap();
        let pp = d(b"pp");
        assert_eq!(d(b"pp\n"), pp);
        assert_eq!(d(b"pp\nsecond line"), pp);
        assert_eq!(d(b"pp\0tail"), pp);
        assert_ne!(d(b"pp\r\n"), pp, "a CR is part of the key, as in zfs load-key");
        let _ = d(b"caf\xe9 latin-1"); // non-UTF-8 is fine
        // hex: exactly 64 digits after the one-newline trim (CRLF = 65 = too long)
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert!(derive_wrapping_key(KeyFormat::Hex, format!("{hex}\n").as_bytes(), 0, 0).is_ok());
        assert_eq!(
            derive_wrapping_key(KeyFormat::Hex, format!("{hex}\r\n").as_bytes(), 0, 0),
            Err(KeyMaterialError::HexLength(65))
        );
        // a hostile iteration count is refused, not ground through
        assert!(matches!(
            derive_wrapping_key(KeyFormat::Passphrase, b"pp", 1, u32::MAX as u64),
            Err(KeyMaterialError::TooManyIterations(_))
        ));
        // an invalid hex digit's error never echoes the key byte
        let bad = format!("q{}", &hex[1..]);
        let e = derive_wrapping_key(KeyFormat::Hex, bad.as_bytes(), 0, 0).unwrap_err();
        assert_eq!(e, KeyMaterialError::HexDigit(1));
        assert!(!e.to_string().contains('q'), "{e}");
    }

    #[test]
    fn hex_roundtrip_and_validation() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF";
        let key = derive_wrapping_key(KeyFormat::Hex, hex.as_bytes(), 0, 0).unwrap();
        assert_eq!(key[0], 0x00);
        assert_eq!(key[15], 0xff);
        assert_eq!(key[31], 0xff);
        // wrong length and non-hex digits are rejected with a message
        assert!(derive_wrapping_key(KeyFormat::Hex, b"abcd", 0, 0).is_err());
        let bad = "zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert!(derive_wrapping_key(KeyFormat::Hex, bad.as_bytes(), 0, 0).is_err());
    }

    #[test]
    fn raw_requires_exact_length() {
        assert!(derive_wrapping_key(KeyFormat::Raw, &[0u8; 32], 0, 0).is_ok());
        assert_eq!(
            derive_wrapping_key(KeyFormat::Raw, &[0u8; 31], 0, 0),
            Err(KeyMaterialError::RawLength(31))
        );
        assert!(derive_wrapping_key(KeyFormat::None, b"x", 0, 0).is_err());
    }
}
