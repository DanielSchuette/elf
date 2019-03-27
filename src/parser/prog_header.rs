/*
 * `prog_header.rs' parses the program header of an ELF file. Correct parsing
 * requires a sufficiently populated `ElfHeader' struct. See `elf_header.rs' for
 * additional information.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 */
use crate::parser;
use crate::utils;

// Parse a single segment of a 64-bit program header segment.
pub fn parse_seg_64_bit(buf: &[u8], elf_h: &parser::ElfHeader,
                        prog_h: &mut parser::ProgHeader, s_no: u16) {
    let start = elf_h.prog_size_hentr * s_no;
    let end = start + elf_h.prog_size_hentr;
    let mut field = 0; /* byte that's currently parsed in segment */
    let mut entr = parser::ProgHeadEntry::new();

    for off in start..end {
        match field {
            0x00 => {
                let field_size = 4;
                let mut reader =
                    utils::read_bytes_into_cursor(buf, off as usize, field_size);
                let entry = utils::unwrap_endian_u32(elf_h, &mut reader);

                let val = match entry {
                    0x00000000 => parser::ProgSegmentType::EntryUnused,
                    0x00000001 => parser::ProgSegmentType::Loadable,
                    0x00000002 => parser::ProgSegmentType::DynLinkInfo,
                    0x00000003 => parser::ProgSegmentType::InterpInfo,
                    0x00000004 => parser::ProgSegmentType::AuxInfo,
                    0x00000005 => parser::ProgSegmentType::Reserved,
                    0x00000006 => parser::ProgSegmentType::ProgHeader,
                    0x60000000...0x6FFFFFFF => parser::ProgSegmentType::OSReserved,
                    0x70000000...0x7FFFFFFF => parser::ProgSegmentType::CPUReserved,
                    _ => panic!(format!("Cannot interpret segment type {}", entry)),
                };

                field += 1;
                entr.s_type = val;
            }
            0x04 => {
                let field_size = 4;
                let mut reader =
                    utils::read_bytes_into_cursor(buf, off as usize, field_size);
                let entry = utils::unwrap_endian_u32(elf_h, &mut reader);

                let val = match entry {
                    0x01 => parser::ProgHeadFlag::Executable,
                    0x02 => parser::ProgHeadFlag::Writable,
                    0x03 => parser::ProgHeadFlag::WriteExecutable,
                    0x04 => parser::ProgHeadFlag::Readable,
                    0x05 => parser::ProgHeadFlag::ReadExecutable,
                    0x06 => parser::ProgHeadFlag::ReadWritable,
                    0x07 => parser::ProgHeadFlag::ReadWriteExecutable,
                    _ => panic!(format!("Cannot interpret flag {}", entry)),
                };

                field += 1;
                entr.flags = val;
            }
            0x08 => {
                let field_size = 8;
                let mut reader =
                    utils::read_bytes_into_cursor(buf, off as usize, field_size);
                let val = utils::unwrap_endian_u64(elf_h, &mut reader);

                field += 1;
                entr.d_off = val;
            }
            0x10 => {
                let field_size = 8;
                let mut reader =
                    utils::read_bytes_into_cursor(buf, off as usize, field_size);
                let val = utils::unwrap_endian_u64(elf_h, &mut reader);

                field += 1;
                entr.v_addr = val;
            }
            0x18 => {
                let field_size = 8;
                let mut reader =
                    utils::read_bytes_into_cursor(buf, off as usize, field_size);
                let val = utils::unwrap_endian_u64(elf_h, &mut reader);

                field += 1;
                entr.p_addr = val;
            }
            0x20 => {
                let field_size = 8;
                let mut reader =
                    utils::read_bytes_into_cursor(buf, off as usize, field_size);
                let val = utils::unwrap_endian_u64(elf_h, &mut reader);

                field += 1;
                entr.f_size = val;
            }
            0x28 => {
                let field_size = 8;
                let mut reader =
                    utils::read_bytes_into_cursor(buf, off as usize, field_size);
                let val = utils::unwrap_endian_u64(elf_h, &mut reader);

                field += 1;
                entr.mem_size = val;
            }
            0x30 => {
                let field_size = 8;
                let mut reader =
                    utils::read_bytes_into_cursor(buf, off as usize, field_size);
                let val = utils::unwrap_endian_u64(elf_h, &mut reader);

                field += 1;
                entr.align = val;
            }
            _ => field += 1, /* move to next field whenever `off' and `field' */
                             /* are not at the exact start of a field */
        }
    }

    prog_h.entr.push(entr);
}

// 32-bit equivalent of `parse_seg_32_bit'.
pub fn parse_seg_32_bit() {}
