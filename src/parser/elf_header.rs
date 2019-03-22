/*
 * `elf_headers.rs' parses the platform-independent, first part of the ELF
 * header (do not confuse with the program header). Parsing of the 32-bit and
 * 64-bit parts is done in `elf_header_XX_bit.rs', respectively.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 */
use std::str;

use crate::parser;

const PARSE_LIMIT_MIN: usize = 0;
const PARSE_LIMIT_MAX: usize = 24;

// TODO: Documentation.
// FIXME: Generalize function with respect to smaller buffers.
pub fn parse(buf: &[u8], bc: usize, header: &mut parser::ElfHeader) -> isize {
    /*
     * Stop early if called with `bc' outside the range of this function.
     * If the last condition is not matched (i.e. 20 < `bc' < 25), -1 is
     * returned to indicate to the caller that this fn is not responsible
     * for parsing the current byte offset.
     */
    if (bc > PARSE_LIMIT_MAX) || (bc < PARSE_LIMIT_MIN) {
        return -1;
    }

    // match the user-provided bytecode with the appropriate action
    match bc {
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
            let elf_in_ascii =
                str::from_utf8(&buf[bc + 1..bc + 4]).expect("Cannot read `ELF' string in header.");
            if elf_in_ascii != parser::ELF_NAME {
                let err = format!(
                    "Did not find {} string in header, found {} instead",
                    parser::ELF_NAME,
                    elf_in_ascii
                );
                panic!(err);
            }
            (parser::ELF_NAME.len() + 1) as isize /* return bytes to consume */
        }
        4 => {
            let platform = buf[bc];
            let platform = match platform {
                1 => parser::PlatformBits::Bits32,
                2 => parser::PlatformBits::Bits64,
                _ => {
                    let err = format!("Cannot interpret platform code {}, expect 1 or 2", platform);
                    panic!(err);
                }
            };
            header.platform_bits = platform;
            1
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
            1
        }
        6 => {
            header.header_version = buf[bc];
            1
        }
        7 => {
            header.abi = buf[bc];
            1
        }
        8 => {
            // skip_padding(&mut bc, 8);
            8
        }
        16 => {
            let elf_type = buf[bc];
            let elf_type = match elf_type {
                1 => parser::ElfType::Relocatable,
                2 => parser::ElfType::Executable,
                3 => parser::ElfType::Shared,
                4 => parser::ElfType::Core,
                _ => {
                    let err = format!("Cannot interpret file type {}, expect one of 1-4", elf_type);
                    panic!(err);
                }
            };
            header.elf_type = elf_type;
            2 /* second byte carries no information ? it's skipped */
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
                    let err = format!("Cannot interpret unknown instruction set code {}", iset);
                    panic!(err);
                }
            };
            header.instruction_set = iset;
            2 /* again, no information in second byte ? */
        }
        20 => {
            // currently, only the first of the next 4 bytes encodes
            // the elf version, but this might change in the future
            header.version = buf[bc];
            4 /* skip 4 bytes at once */
        }
        // TODO: at this point, platform-specific parsing must be
        // done, because 32-bit headers are smaller then the 64-bit
        // counterpart. Call specialized functions from here.

        // FIXME: for debugging, cycle to the end of the elf file
        _ => 1,
    }
}
