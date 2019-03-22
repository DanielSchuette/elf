/*
 * `elf' is a command line utility that reads the binary ELF format.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 *
 * Dev logs:
 * FIXME: Enable all linter flags before deployment.
 * TODO: Parse platform-specific headers.
 * TODO: Parse program headers.
 * TODO: Parse data section.
 * TODO: Parse text section (symbols?).
 */
#![allow(dead_code)]
#![allow(unused)]

pub mod parser;

use std::fs;
use std::io::prelude::*;
use std::str;

use parser::elf_header;
use parser::elf_header_32_bit;
use parser::elf_header_64_bit;

const BUF_SIZE: usize = 4096;
const ELF_PATH: &str = "../data/elf"; /* FIXME: get path via cli soon */

fn main() {
    // open elf file and access metadata to verify correct
    // length and file type
    let mut f = fs::File::open(ELF_PATH).expect("Cannot open file");
    let metadata = f.metadata().expect("Cannot read file metadata");
    let file_len = metadata.len();

    if (!metadata.is_file()) || (file_len < parser::ELF_HEADER_LEN) {
        panic!(format!("{} is not a file or empty.", ELF_PATH));
    }

    // read 10 bytes of data at a time from file into `buf'
    let mut buf = [0; BUF_SIZE];
    let mut bytes_total = 0; /* total number of bytes read */
    let mut bytes_read = 1; /* bytes read from file during last read */
    let mut bc = 0; /* bytes consumed during parsing */

    let mut header: parser::ElfHeader = parser::ElfHeader::new();

    while bytes_read > 0 {
        bytes_read = read_into_buf(&mut f, &mut buf);

        /*
         * Parse header. Must be read in a large chunk of e.g. 4096 bytes,
         * otherwise multi-byte data might not be read properly.
         */
        if bytes_total == 0 {
            while bc < buf.len() {
                bc += elf_header::parse(&buf, bc, &mut header);
            }
        }
        print_buffer(&buf[bc..]); /* if everything is consumed, print nothing */
        bytes_total += bytes_read;
    }

    // ensure that every single byte was read
    validate_read(bytes_total, file_len as usize);

    // print the parsed header
    header.print();
}

// Read as many bytes from `file' into `buf' as possible. The actual number is
// limited by the length of `buf' and the number of bytes left in `file'. The
// number of bytes read is then returned. This fn panics on errors.
fn read_into_buf(file: &mut fs::File, mut buf: &mut [u8]) -> usize {
    file.read(&mut buf).expect("Cannot read from file")
}

// Print the contents of a byte buffer. For debugging purposes.
fn print_buffer(buf: &[u8]) {
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
fn validate_read(total: usize, file_len: usize) {
    assert_eq!(total, file_len, "Did not read as many bytes as expected.");
}
