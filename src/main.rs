/*
 * TEMP_NAME is a command line utility that reads the binary elf format.
 * FIXME: Enable all linter flags before deployment.
 */
#![allow(dead_code)]
#![allow(unused)]
use std::fs;
use std::io::prelude::*;
use std::str;

const BUF_SIZE: usize = 4096;
const ELF_PATH: &str = "../data/elf";
const ELF_HEADER_LEN: u64 = 1;
const ELF_MAGIC_NUM: u8 = 0x7f;
const ELF_NAME: &str = "ELF";

#[derive(Debug)]
enum PlatformBits {
    Bits64,
    Bits32,
    Unknown,
}

#[derive(Debug)]
enum Endianness {
    Little,
    Big,
    Unknown,
}

#[derive(Debug)]
enum ElfType {
    Relocatable,
    Executable,
    Shared,
    Core,
    Unknown,
}

#[derive(Debug)]
enum InstructionSet {
    NoSpecific,
    Sparc,
    X86,
    MIPS,
    PowerPC,
    ARM,
    SuperH,
    IA64,
    X86_64,
    AArch64,
}

// Header data is parsed into and available through this struct.
struct ElfHeader {
    elf_type: ElfType,
    platform_bits: PlatformBits,
    endianness: Endianness,
    version: u8,
    header_version: u8,
    abi: u8, /* 0 for System V, maybe others */
    instruction_set: InstructionSet,
}

impl ElfHeader {
    // create a new `ElfHeader' struct with default values
    fn new() -> ElfHeader {
        ElfHeader {
            elf_type: ElfType::Unknown,
            platform_bits: PlatformBits::Unknown,
            endianness: Endianness::Unknown,
            version: 0,
            header_version: 0,
            abi: 0,
            instruction_set: InstructionSet::NoSpecific,
        }
    }

    // pretty-print an `ElfHeader' struct, mainly for debugging
    fn print(&self) {
        println!("Platform: {:?}", self.platform_bits);
        println!("Endianness: {:?}", self.endianness);
        println!("ELF version: {:?}", self.version);
        println!("Header version: {:?}", self.header_version);
        println!("Operating System ABI: {:?}", self.abi);
        println!("Type: {:?}", self.elf_type);
        println!("Instruction set: {:?}", self.instruction_set);
    }
}

fn main() {
    // open elf file and access metadata to verify correct
    // length and file type
    let mut f = fs::File::open(ELF_PATH).expect("Cannot open file");
    let metadata = f.metadata().expect("Cannot read file metadata");
    let file_len = metadata.len();

    if (!metadata.is_file()) || (file_len < ELF_HEADER_LEN) {
        panic!(format!("{} is not a file or empty.", ELF_PATH));
    }

    // read 10 bytes of data at a time from file into `buf'
    let mut buf = [0; BUF_SIZE];
    let mut bytes_total = 0; /* total number of bytes read */
    let mut bytes_read = 1; /* bytes read from file during last read */
    let mut bc = 0; /* bytes consumed during parsing */

    let mut header: ElfHeader = ElfHeader::new();

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
                        if buf[bc] != ELF_MAGIC_NUM {
                            let err = format!(
                                "Did not find magic number {}, found {} instead.",
                                ELF_MAGIC_NUM, buf[bc]
                            );
                            panic!(err);
                        }
                        // the next 3 bytes must be ascii chars `ELF'
                        let elf_in_ascii = str::from_utf8(&buf[bc + 1..bc + 4])
                            .expect("Cannot read `ELF' string in header.");
                        if elf_in_ascii != ELF_NAME {
                            let err = format!(
                                "Did not find {} string in header, found {} instead",
                                ELF_NAME, elf_in_ascii
                            );
                            panic!(err);
                        }
                        bc += ELF_NAME.len() + 1; /* consume bytes */
                    }
                    4 => {
                        let platform = buf[bc];
                        let platform = match platform {
                            1 => PlatformBits::Bits32,
                            2 => PlatformBits::Bits64,
                            _ => {
                                let msg = format!(
                                    "Cannot interpret platform code {}, expect 1 or 2",
                                    platform
                                );
                                panic!(msg);
                            }
                        };
                        header.platform_bits = platform;
                        bc += 1;
                    }
                    5 => {
                        let endian = buf[bc];
                        let endian = match endian {
                            1 => Endianness::Little,
                            2 => Endianness::Big,
                            _ => {
                                let msg = format!(
                                    "Cannot interpret code for endianness {}, expect 1 or 2",
                                    endian
                                );
                                panic!(msg);
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
                            1 => ElfType::Relocatable,
                            2 => ElfType::Executable,
                            3 => ElfType::Shared,
                            4 => ElfType::Core,
                            _ => {
                                let msg = format!(
                                    "Cannot interpret file type {}, expect one of 1-4",
                                    elf_type
                                );
                                panic!(msg);
                            }
                        };
                        header.elf_type = elf_type;
                        bc += 2; /* second byte carries no information ? */
                    }
                    18 => {
                        let iset = buf[bc];
                        let iset = match iset {
                            0x00 => InstructionSet::NoSpecific,
                            0x02 => InstructionSet::Sparc,
                            0x03 => InstructionSet::X86,
                            0x08 => InstructionSet::MIPS,
                            0x14 => InstructionSet::PowerPC,
                            0x28 => InstructionSet::ARM,
                            0x2a => InstructionSet::SuperH,
                            0x32 => InstructionSet::IA64,
                            0x3e => InstructionSet::X86_64,
                            0xb7 => InstructionSet::AArch64,
                            _ => {
                                let msg = format!(
                                    "Cannot interpret unknown instruction set code {}",
                                    iset
                                );
                                panic!(msg);
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
