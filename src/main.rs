/*
 * `elf' is a command line utility that reads the binary ELF format.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 *
 * Dev logs:
 * TODO: Parse program header.
 * TODO: Parse section header.
 * TODO: Parse and print data section.
 * TODO: Parse and print text section (symbol table?).
 * TODO: Improve CLI.
 */
extern crate clap;
pub mod parser;
pub mod utils;

use clap::{App, Arg};
use parser::{get_elf_header, get_prog_header};
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
                                                          .help("Run in debug-mode (disabled by default)")
                                                          .takes_value(false)
                                                          .required(false))
                              .arg(Arg::with_name("HEADER").short("e")
                                                           .long("header")
                                                           .help("Print the ELF header (disabled by default)")
                                                           .takes_value(false)
                                                           .required(false))
                              .get_matches();

    let elf_path = cli_args.value_of("PATH").unwrap();
    let debug_mode = if cli_args.is_present("DEBUG") {
        true
    } else {
        false
    };
    let print_header = if cli_args.is_present("HEADER") {
        true
    } else {
        false
    };
    let configs = utils::Config { elf_path,
                                  debug_mode,
                                  print_header };

    // open elf file, get metadata to verify correct length and file type
    let mut f = fs::File::open(elf_path).expect("Cannot open file");
    let metadata = f.metadata().expect("Cannot read file metadata");
    let file_size = metadata.len();

    if (!metadata.is_file()) || ((file_size as usize) < parser::ELF_HEADER_LEN) {
        panic!(format!("{} is not a file or empty.", elf_path));
    }

    // parse, validate and print ELF header
    let mut elf_h = get_elf_header(&mut f, &configs);
    elf_h.file_size = file_size;

    assert!(elf_h.validate());
    if configs.print_header {
        elf_h.print();
    }

    // parse and print program header table
    let prog_h = get_prog_header(&mut f, &elf_h, &configs);

    if configs.print_header {
        prog_h.print();
    }
}
