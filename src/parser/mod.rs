/*
 * `parser/' contains submodules for parsing the ELF and program headers as
 * well as the data and text sections of an ELF file. Structs, constants and
 * enums that are shared between modules are defined here.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 */
pub mod elf_header;
pub mod elf_header_32_bit;
pub mod elf_header_64_bit;

pub const ELF_HEADER_LEN: u64 = 0x40;
pub const ELF_MAGIC_NUM: u8 = 0x7f;
pub const ELF_NAME: &str = "ELF";

#[derive(Debug)]
pub enum PlatformBits {
    Bits64,
    Bits32,
    Unknown,
}

#[derive(Debug)]
pub enum Endianness {
    Little,
    Big,
    Unknown,
}

#[derive(Debug)]
pub enum ElfType {
    Relocatable,
    Executable,
    Shared,
    Core,
    Unknown,
}

#[derive(Debug)]
pub enum InstructionSet {
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
pub struct ElfHeader {
    pub elf_type: ElfType,
    pub platform_bits: PlatformBits,
    pub endianness: Endianness,
    pub version: u32,
    pub header_version: u8,
    pub abi: u8, /* 0 for System V standard, maybe others */
    pub instruction_set: InstructionSet,

    // sizes of the following fields are platform dependent
    pub flags: u32, /* TODO: not implemented, always 0 */
    pub header_size: u16,

    pub prog_entry_pos: u64,  /* program entry position */
    pub prog_tbl_pos: u64,    /* program header table position */
    pub sec_tbl_pos: u64,     /* section header table position */
    pub prog_size_hentr: u16, /* size of entry in program header */
    pub prog_no_hentr: u16,   /* number of entries in program header */
    pub sec_size_hentr: u16,  /* size of entry in section header */
    pub sec_no_entr: u16,     /* number of entries in section header */
    pub sec_tbl_names_pos: u16, /* index of section names in section */
                              /* header table */
}

impl ElfHeader {
    // create a new `ElfHeader' struct with default values
    pub fn new() -> ElfHeader {
        ElfHeader { elf_type: ElfType::Unknown,
                    platform_bits: PlatformBits::Unknown,
                    endianness: Endianness::Unknown,
                    version: 0,
                    header_version: 0,
                    abi: 0,
                    instruction_set: InstructionSet::NoSpecific,
                    flags: 0,
                    header_size: 0,
                    prog_entry_pos: 0,
                    prog_tbl_pos: 0,
                    sec_tbl_pos: 0,
                    prog_size_hentr: 0,
                    prog_no_hentr: 0,
                    sec_size_hentr: 0,
                    sec_no_entr: 0,
                    sec_tbl_names_pos: 0 }
    }

    // pretty-print an `ElfHeader' struct, mainly for debugging
    pub fn print(&self) {
        println!("Platform: {:?}", self.platform_bits);
        println!("Endianness: {:?}", self.endianness);
        println!("ELF version: {:?}", self.version);
        println!("Header version: {:?}", self.header_version);
        println!("Operating System ABI: {:?}", self.abi);
        println!("Type: {:?}", self.elf_type);
        println!("Instruction set: {:?}", self.instruction_set);
        println!("Flags: {:?}", self.flags);
        println!("Header size: {:?}", self.header_size);
        println!("Program entry position: {:?}", self.prog_entry_pos);
        println!("Program header table position: {:?}", self.prog_tbl_pos);
        println!("Section header table position: {:?}", self.sec_tbl_pos);
        println!("Program header entry size: {:?}", self.prog_size_hentr);
        println!("Number of program header entries: {:?}", self.prog_no_hentr);
        println!("Section header entry size: {:?}", self.sec_size_hentr);
        println!("Number of section header entries: {:?}", self.sec_no_entr);
        println!("Index of section names in section header: {:?}",
                 self.sec_tbl_names_pos);
    }
}
