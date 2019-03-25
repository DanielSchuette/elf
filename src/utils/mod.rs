/*
 * A set of utility functions.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 */
extern crate byteorder;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};

use std::fs;
use std::io::prelude::*;
use std::io::Cursor;

use crate::parser;

// Read `size' bytes from a `buf' into a cursor for further manipulation, e.g.
// the conversion into u64. Reading starts at `offset'.
pub fn read_bytes_into_cursor(buf: &[u8], offset: usize, size: usize)
                              -> Cursor<Vec<u8>> {
    let mut fields = vec![];
    let field_size = 8;

    for i in 0..field_size {
        fields.push(buf[offset + i]);
    }

    Cursor::new(fields)
}

pub fn unwrap_endian_u16(header: &parser::ElfHeader,
                         reader: &mut std::io::Cursor<Vec<u8>>)
                         -> u16 {
    match header.endianness {
        parser::Endianness::Big => reader.read_u16::<BigEndian>().unwrap(),
        parser::Endianness::Little => reader.read_u16::<LittleEndian>().unwrap(),
        _ => panic!("Failed because endianness could not be determined"),
    }
}

pub fn unwrap_endian_u32(header: &parser::ElfHeader,
                         reader: &mut std::io::Cursor<Vec<u8>>)
                         -> u32 {
    match header.endianness {
        parser::Endianness::Big => reader.read_u32::<BigEndian>().unwrap(),
        parser::Endianness::Little => reader.read_u32::<LittleEndian>().unwrap(),
        _ => panic!("Failed because endianness could not be determined"),
    }
}

pub fn unwrap_endian_u64(header: &parser::ElfHeader,
                         reader: &mut std::io::Cursor<Vec<u8>>)
                         -> u64 {
    match header.endianness {
        parser::Endianness::Big => reader.read_u64::<BigEndian>().unwrap(),
        parser::Endianness::Little => reader.read_u64::<LittleEndian>().unwrap(),
        _ => panic!("Failed because endianness could not be determined"),
    }
}

// Read as many bytes from `file' into `buf' as possible. The actual number is
// limited by the length of `buf' and the number of bytes left in `file'. The
// number of bytes read is then returned. This fn panics on errors.
pub fn read_into_buf(file: &mut fs::File, mut buf: &mut [u8]) -> usize {
    file.read(&mut buf).expect("Cannot read from file")
}

// Print the contents of a byte buffer. For debugging purposes.
pub fn print_buffer(buf: &[u8]) {
    for byte in buf.iter() {
        if byte.is_ascii_alphabetic() {
            let c = *byte as char;
            if c == ' ' {
                print!("space ");
            } else {
                print!("{} ", c);
            }
        } else {
            print!("{} ", byte);
        }
    }
}

// Panic if the `total' and `file_len' are not equal.
pub fn validate_read(total: usize, file_len: usize) {
    assert_eq!(total, file_len, "Did not read as many bytes as expected.");
}
