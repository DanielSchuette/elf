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
pub mod utils;

use std::fs;

use parser::elf_header;
use parser::elf_header_32_bit;
use parser::elf_header_64_bit;
use utils::{print_buffer, read_into_buf, validate_read};

const BUF_SIZE: usize = 4096;
const ELF_PATH: &str = "../data/elf"; /* FIXME: get path via cli soon */

fn main() {
    // open elf file and access metadata to verify correct
    // length and file type
    let mut f = fs::File::open(ELF_PATH).expect("Cannot open file");
    let metadata = f.metadata().expect("Cannot read file metadata");
    let file_size = metadata.len();

    if (!metadata.is_file()) || (file_size < parser::ELF_HEADER_LEN) {
        panic!(format!("{} is not a file or empty.", ELF_PATH));
    }

    // read BUF_SIZE bytes of data at a time from file into `buf'
    let mut buf = [0; BUF_SIZE];
    let mut b_total = 0; /* total number of bytes read */
    let mut b_read = 1; /* bytes read from file during last read */
    let mut offset = 0; /* bytes consumed during every parsing iteration */
    let mut iteration = 0; /* number of current parsing iteration/buf */

    let mut header: parser::ElfHeader = parser::ElfHeader::new();

    while b_read > 0 {
        b_read = read_into_buf(&mut f, &mut buf);

        /*
         * Parse header. Better be read in a larger chunk of e.g. 4096 bytes,
         * otherwise multi-byte data might not be read properly. Parsing
         * functions return -1 early if they are not responsible for a certain
         * offset `bc'. This behavior protects against wrong increments and
         * lossy parsing but might be replace by an Option<usize> return type.
         */
        let buf_size = buf.len();
        while offset < buf_size {
            // the `offset' is used to control the loop, the absolute position
            // within the ELF file must be calculated using the iteration number
            // and the constant buffer size
            let position = offset + (iteration * BUF_SIZE);
            let mut status: isize;

            status = elf_header::parse(&buf, offset, position, &mut header);
            if status != -1 {
                offset += status as usize;
                continue;
            }

            status = elf_header_64_bit::parse(&buf, offset, position, &mut header);
            if status != -1 {
                offset += status as usize;
                continue;
            }

            // apparently, `offset' couldn't be handled yet, keep cycling to
            // recover eventually or consume the entire buffer and return
            offset += 1;
        }

        print_buffer(&buf[offset..]); /* w/o bugs, offset==buf.len */
        b_total += b_read; /* increment total number of overall read bytes */
        iteration += 1; /* increment iteration counter */
        offset = 0; /* reset offset into buffer for next iteration */
    }

    // ensure that every single byte was read
    validate_read(b_total, file_size as usize);

    // print the parsed header
    header.print();
}
