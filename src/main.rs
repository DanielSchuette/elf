/*
 * TEMP_NAME is a command line utility that reads the binary elf format.
 * FIXME: Enable all linter flags before deployment.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 */
#![allow(dead_code)]
#![allow(unused)]

mod parser;

use std::fs;
use std::io::prelude::*;
use std::str;

use parser::elf_header;

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
                match bc {
                    //
                    0 => {
                        // every valid elf file starts with magic number
                        if buf[bc] != parser::ELF_MAGIC_NUM {
                            let err = format!(
                                "Did not find magic number {}, found {} instead.",
                                parser::ELF_MAGIC_NUM,
                                buf[bc]
                            );
                            panic!(err);
                        }
                        // the next 3 bytes must be ascii chars `ELF'
                        let elf_in_ascii = str::from_utf8(&buf[bc + 1..bc + 4])
                            .expect("Cannot read `ELF' string in header.");
                        if elf_in_ascii != parser::ELF_NAME {
                            let err = format!(
                                "Did not find {} string in header, found {} instead",
                                parser::ELF_NAME,
                                elf_in_ascii
                            );
                            panic!(err);
                        }
                        bc += parser::ELF_NAME.len() + 1; /* consume bytes */
                    }
                    4 => {
                        let platform = buf[bc];
                        let platform = match platform {
                            1 => parser::PlatformBits::Bits32,
                            2 => parser::PlatformBits::Bits64,
                            _ => {
                                let err = format!(
                                    "Cannot interpret platform code {}, expect 1 or 2",
                                    platform
                                );
                                panic!(err);
                            }
                        };
                        header.platform_bits = platform;
                        bc += 1;
                    }
                    5 => {
                        let endian = buf[bc];
                        let endian = match endian {
                            1 => parser::Endianness::Little,
                            2 => parser::Endianness::Big,
                            _ => {
                                let err = format!(
                                    "Cannot interpret code for endianness {}, expect 1 or 2",
                                    endian
                                );
                                panic!(err);
                            }
                        };
                        header.endianness = endian;
                        bc += 1;
                    }
                    6 => {
                        header.header_version = buf[bc];
                        bc += 1;
                    }
                    7 => {
                        header.abi = buf[bc];
                        bc += 1;
                    }
                    8 => {
                        skip_padding(&mut bc, 8);
                    }
                    16 => {
                        let elf_type = buf[bc];
                        let elf_type = match elf_type {
                            1 => parser::ElfType::Relocatable,
                            2 => parser::ElfType::Executable,
                            3 => parser::ElfType::Shared,
                            4 => parser::ElfType::Core,
                            _ => {
                                let err = format!(
                                    "Cannot interpret file type {}, expect one of 1-4",
                                    elf_type
                                );
                                panic!(err);
                            }
                        };
                        header.elf_type = elf_type;
                        bc += 2; /* second byte carries no information ? */
                    }
                    18 => {
                        let iset = buf[bc];
                        let iset = match iset {
                            0x00 => parser::InstructionSet::NoSpecific,
                            0x02 => parser::InstructionSet::Sparc,
                            0x03 => parser::InstructionSet::X86,
                            0x08 => parser::InstructionSet::MIPS,
                            0x14 => parser::InstructionSet::PowerPC,
                            0x28 => parser::InstructionSet::ARM,
                            0x2a => parser::InstructionSet::SuperH,
                            0x32 => parser::InstructionSet::IA64,
                            0x3e => parser::InstructionSet::X86_64,
                            0xb7 => parser::InstructionSet::AArch64,
                            _ => {
                                let err = format!(
                                    "Cannot interpret unknown instruction set code {}",
                                    iset
                                );
                                panic!(err);
                            }
                        };
                        header.instruction_set = iset;
                        bc += 2; /* second byte carries no information ? */
                    }
                    20 => {
                        // currently, only the first of the next 4 bytes encodes
                        // the elf version, but this might change in the future
                        header.version = buf[bc];
                        bc += 4; /* skip 4 bytes at once */
                    }
                    // TODO: at this point, platform-specific parsing must be
                    // done, because 32-bit headers are smaller then the 64-bit
                    // counterpart

                    // FIXME: for debugging, cycle to the end of the elf file
                    _ => bc += 1,
                }
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

// Add padding to a counter. For code readability.
fn skip_padding(counter: &mut usize, padding: usize) {
    *counter += padding;
}
