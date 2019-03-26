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
 */
#![allow(dead_code)]
#![allow(unused)]

pub mod parser;
pub mod utils;

use std::env;
use std::fs;

use parser::get_header;

const ELF_PATH: &str = "../data/elf_64bit";
const DEBUG: bool = false;

fn main() {
    // collect cli arguments
    let args: Vec<String> = env::args().collect();
    let elf_path = &args[1];

    // open elf file, get metadata to verify correct length and file type
    let mut f = fs::File::open(elf_path).expect("Cannot open file");
    let metadata = f.metadata().expect("Cannot read file metadata");
    let file_size = metadata.len();

    if (!metadata.is_file()) || ((file_size as usize) < parser::ELF_HEADER_LEN) {
        panic!(format!("{} is not a file or empty.", ELF_PATH));
    }

    // parse and print ELF header
    let mut header = get_header(&mut f);
    header.file_size = file_size;
    header.print();

    // TODO: parse additional sections based on header data
}
