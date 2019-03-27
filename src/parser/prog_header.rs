/*
 * `prog_header.rs' parses the program header of an ELF file. Correct parsing
 * requires a sufficiently populated `ElfHeader' struct. See `elf_header.rs' for
 * additional information.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 */
use crate::parser;

pub fn parse_segment(_buf: &[u8], elf_h: &parser::ElfHeader,
                     prog_h: &mut parser::ProgHeader, s_no: u16) {
    let start = elf_h.prog_size_hentr * s_no;
    let _end = start + elf_h.prog_size_hentr;
    let entr = parser::ProgHeadEntry::new();

    // TODO: parse before push
    prog_h.entr.push(entr);
}
