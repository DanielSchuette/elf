/*
 * `elf' is a command line utility that reads the binary ELF format.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 *
 * Dev logs:
 * FIXME: Enable all linter flags before deployment.
 * TODO: Parse program headers.
 * TODO: Parse data section.
 * TODO: Parse text section (symbols?).
 * TODO: Get path to elf file via CLI.
 */
#![allow(dead_code)]
#![allow(unused)]

pub mod parser;
pub mod utils;

use std::fs;

use parser::get_header;

const ELF_PATH: &str = "../data/elf";

fn main() {
    // open elf file, get metadata to verify correct length and file type
    let mut f = fs::File::open(ELF_PATH).expect("Cannot open file");
    let metadata = f.metadata().expect("Cannot read file metadata");
    let file_size: usize = metadata.len() as usize;

    if (!metadata.is_file()) || (file_size < parser::ELF_HEADER_LEN) {
        panic!(format!("{} is not a file or empty.", ELF_PATH));
    }

    // parse and print ELF header
    let header = get_header(&mut f);
    header.print(); /* print parsed header */
}
