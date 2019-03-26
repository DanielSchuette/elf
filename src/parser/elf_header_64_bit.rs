/*
 * `elf_header_64_bit.rs' parses the platform-specific parts of the ELF header
 * if a 64-bit file is detected.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 */
use crate::parser;
use crate::utils;

const PARSE_LIMIT_MIN: usize = 24;
const PARSE_LIMIT_MAX: usize = 63;

// The same signature as elf_header::parse(). See that function for detailed
// documentation.
pub fn parse(buf: &[u8], offset: usize, header: &mut parser::ElfHeader)
             -> Option<usize> {
    if (offset < PARSE_LIMIT_MIN)
       || (offset > PARSE_LIMIT_MAX)
       || (header.platform_bits != parser::PlatformBits::Bits64)
    {
        return None;
    }

    match offset {
        24 => {
            let field_size = parser::FIELD_SIZE_64;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            header.prog_entry_pos = utils::unwrap_endian_u64(header, &mut reader);

            Some(field_size)
        }
        32 => {
            let field_size = parser::FIELD_SIZE_64;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            header.prog_tbl_pos = utils::unwrap_endian_u64(header, &mut reader);

            Some(field_size)
        }
        40 => {
            let field_size = parser::FIELD_SIZE_64;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            header.sec_tbl_pos = utils::unwrap_endian_u64(header, &mut reader);

            Some(field_size)
        }
        48 => Some(parser::FIELD_SIZE_32), /* TODO: don't ignore flags */
        52 => {
            let field_size = parser::FIELD_SIZE_16;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let entry = utils::unwrap_endian_u16(header, &mut reader);
            header.header_size = entry;

            Some(field_size)
        }
        54 => {
            let field_size = parser::FIELD_SIZE_16;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let entry = utils::unwrap_endian_u16(header, &mut reader);
            header.prog_size_hentr = entry;

            Some(field_size)
        }
        56 => {
            let field_size = parser::FIELD_SIZE_16;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let entry = utils::unwrap_endian_u16(header, &mut reader);
            header.prog_no_hentr = entry;

            Some(field_size)
        }
        58 => {
            let field_size = parser::FIELD_SIZE_16;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let entry = utils::unwrap_endian_u16(header, &mut reader);
            header.sec_size_hentr = entry;

            Some(field_size)
        }
        60 => {
            let field_size = parser::FIELD_SIZE_16;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let entry = utils::unwrap_endian_u16(header, &mut reader);
            header.sec_no_entr = entry;

            Some(field_size)
        }
        62 => {
            let field_size = 2;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let entry = utils::unwrap_endian_u16(header, &mut reader);
            header.sec_tbl_names_pos = entry;

            Some(field_size)
        }
        _ => Some(1),
    }
}
