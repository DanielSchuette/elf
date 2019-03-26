/*
 * `elf_headers.rs' parses the platform-independent, first part of the ELF
 * header (do not confuse with the program header). Parsing of the 32-bit and
 * 64-bit parts is done in `elf_header_XX_bit.rs', respectively.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 */
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use std::io::Cursor;
use std::str;

use crate::parser;
use crate::utils;

const PARSE_LIMIT_MAX: usize = 23;

// `parse' takes a byte buffer and an `offset' into `buf'. It then
// matches that value with the appropriate ELF section and adds the
// interpreted data to the mutably borrowed `header' struct. The caller
// has to make sure that no out-of-bounds access is performed on `buf'.
// FIXME: Generalize function with respect to smaller buffers.
// FIXME: Return a Result<usize, CustomErrorType> instead of an isize
//        and panicking all the time.
pub fn parse(buf: &[u8], offset: usize, header: &mut parser::ElfHeader)
             -> Option<usize> {
    /*
     * Stop early if called with a `position' outside the range of this function
     * (i.e. 20 < `offset' < 25), -1 is returned to indicate to the caller that
     * this function is not responsible for parsing the current byte offset.
     */
    if offset > PARSE_LIMIT_MAX {
        return None;
    }

    // match the user-provided position within the ELF file with the appropriate
    // parsing action
    match offset {
        0 => {
            // every valid elf file starts with magic number
            if buf[offset] != parser::ELF_MAGIC_NUM {
                let err = format!("Did not find magic number {}, found {} instead.",
                                  parser::ELF_MAGIC_NUM,
                                  buf[offset]);
                panic!(err);
            }
            // the next 3 bytes must be ascii chars `ELF'
            let elf_in_ascii = str::from_utf8(&buf[offset + 1..offset + 4])
                .expect("Cannot read `ELF' string in header.");
            if elf_in_ascii != parser::ELF_NAME {
                let err =
                    format!("Did not find {} string in header, found {} instead",
                            parser::ELF_NAME,
                            elf_in_ascii);
                panic!(err);
            }
            Some(parser::ELF_NAME.len() + 1)
        }
        4 => {
            let platform = buf[offset];
            let platform = match platform {
                1 => parser::PlatformBits::Bits32,
                2 => parser::PlatformBits::Bits64,
                _ => {
                    let err =
                        format!("Cannot interpret platform code {}, expect 1 or 2",
                                platform);
                    panic!(err);
                }
            };
            header.platform_bits = platform;
            Some(1)
        }
        5 => {
            let endian = buf[offset];
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
            Some(1)
        }
        6 => {
            header.header_version = buf[offset];
            Some(1)
        }
        7 => {
            let field_val = buf[offset];
            let abi = match field_val {
                0x00 => parser::TargetABI::SystemV,
                0x01 => parser::TargetABI::HPUX,
                0x02 => parser::TargetABI::NetBSD,
                0x03 => parser::TargetABI::Linux,
                0x04 => parser::TargetABI::GNUHurd,
                0x06 => parser::TargetABI::Solaris,
                0x07 => parser::TargetABI::AIX,
                0x08 => parser::TargetABI::IRIX,
                0x09 => parser::TargetABI::FreeBSD,
                0x0a => parser::TargetABI::Tru64,
                0x0b => parser::TargetABI::NovellModesto,
                0x0c => parser::TargetABI::OpenBSD,
                0x0d => parser::TargetABI::OpenVMS,
                0x0e => parser::TargetABI::NonStop,
                0x0f => parser::TargetABI::AROS,
                0x10 => parser::TargetABI::FenixOS,
                0x11 => parser::TargetABI::CloudABI,
                _ => {
                    let err = format!(
                        "Cannot interpret code for endianness {}, expect 1 or 2",
                        field_val
                    );
                    panic!(err);
                }
            };
            header.abi = abi;
            Some(1)
        }
        8 => Some(8),
        16 => {
            let field_size = 2;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let field_val = utils::unwrap_endian_u16(header, &mut reader);

            let elf_type = match field_val {
                1 => parser::ElfType::Relocatable,
                2 => parser::ElfType::Executable,
                3 => parser::ElfType::Shared,
                4 => parser::ElfType::Core,
                _ => {
                    let err =
                        format!("Cannot interpret file type {:?}, expect one of 1-4",
                                field_val);
                    panic!(err);
                }
            };
            header.elf_type = elf_type;

            Some(field_size)
        }
        18 => {
            let field_size = 2;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let field_val = utils::unwrap_endian_u16(header, &mut reader);

            let iset = match field_val {
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
                    let err =
                        format!("Cannot interpret unknown instruction set code {}",
                                field_val);
                    panic!(err);
                }
            };
            header.instruction_set = iset;
            Some(field_size)
        }
        20 => {
            let field_size = 4;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            header.version = utils::unwrap_endian_u32(header, &mut reader);

            Some(field_size)
        }
        _ => Some(1),
    }
}
