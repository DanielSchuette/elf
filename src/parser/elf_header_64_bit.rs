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
pub fn parse(buf: &[u8], offset: usize, position: usize,
             header: &mut parser::ElfHeader)
             -> isize {
    if (offset < PARSE_LIMIT_MIN) || (offset > PARSE_LIMIT_MAX) {
        return -1;
    }

    match position {
        24 => {
            let field_size = 8;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            header.prog_entry_pos = utils::unwrap_endian_u64(header, &mut reader);

            field_size as isize
        }
        32 => {
            let field_size = 8;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            header.prog_tbl_pos = utils::unwrap_endian_u64(header, &mut reader);

            field_size as isize
        }
        40 => {
            let field_size = 8;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            header.sec_tbl_pos = utils::unwrap_endian_u64(header, &mut reader);

            field_size as isize
        }
        48 => 4, /* TODO: currently, flags are ignored */
        52 => {
            let field_size = 2;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let entry = utils::unwrap_endian_u16(header, &mut reader);
            header.header_size = entry;

            field_size as isize
        }
        54 => {
            let field_size = 2;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let entry = utils::unwrap_endian_u16(header, &mut reader);
            header.prog_size_hentr = entry;

            field_size as isize
        }
        56 => {
            let field_size = 2;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let entry = utils::unwrap_endian_u16(header, &mut reader);
            header.prog_no_hentr = entry;

            field_size as isize
        }
        58 => {
            let field_size = 2;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let entry = utils::unwrap_endian_u16(header, &mut reader);
            header.sec_size_hentr = entry;

            field_size as isize
        }
        60 => {
            let field_size = 2;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let entry = utils::unwrap_endian_u16(header, &mut reader);
            header.sec_no_entr = entry;

            field_size as isize
        }
        62 => {
            let field_size = 2;
            let mut reader = utils::read_bytes_into_cursor(buf, offset, field_size);

            let entry = utils::unwrap_endian_u16(header, &mut reader);
            header.sec_tbl_names_pos = entry;

            field_size as isize
        }
        _ => 1,
    }
}
