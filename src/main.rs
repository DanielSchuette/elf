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

extern crate clap;
use clap::{App, Arg};

use parser::get_header;
use std::fs;

fn main() {
    // collect cli arguments and initialize config struct
    let cli_args =
        App::new("ELF parser").version("0.0.1")
                              .author("Daniel Schuette <d.schuette@online.de>")
                              .about("Extract information from ELF files.")
                              .arg(Arg::with_name("PATH").short("p")
                                                         .long("path")
                                                         .help("Path to an ELF file")
                                                         .takes_value(true)
                                                         .required(true))
                              .arg(Arg::with_name("DEBUG").short("d")
                                                          .long("debug")
                                                          .help("Run in debug-mode")
                                                          .takes_value(false)
                                                          .required(false))
                              .get_matches();

    let elf_path = cli_args.value_of("PATH").unwrap();
    let debug_mode = if cli_args.is_present("DEBUG") {
        true
    } else {
        false
    };
    let configs = utils::Config { elf_path,
                                  debug_mode };

    // open elf file, get metadata to verify correct length and file type
    let mut f = fs::File::open(elf_path).expect("Cannot open file");
    let metadata = f.metadata().expect("Cannot read file metadata");
    let file_size = metadata.len();

    if (!metadata.is_file()) || ((file_size as usize) < parser::ELF_HEADER_LEN) {
        panic!(format!("{} is not a file or empty.", elf_path));
    }

    // parse and print ELF header
    let mut header = get_header(&mut f, &configs);
    header.file_size = file_size;
    header.print();

    // TODO: parse additional sections based on header data
}
