/*
 * `parser/' contains submodules for parsing the ELF and program headers as
 * well as the data and text sections of an ELF file.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 */
pub mod elf_header;
pub mod elf_header_32_bit;
pub mod elf_header_64_bit;

use crate::utils::{print_buffer, read_into_buf, validate_read};

pub const ELF_HEADER_LEN: usize = 0x40;
pub const ELF_MAGIC_NUM: u8 = 0x7f;
pub const ELF_NAME: &str = "ELF";

pub const FIELD_SIZE_16: usize = 2;
pub const FIELD_SIZE_32: usize = 4;
pub const FIELD_SIZE_64: usize = 8;

#[derive(Debug, PartialEq)]
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

#[derive(Debug)]
pub enum TargetABI {
    NoSpecific,
    SystemV,
    HPUX,
    NetBSD,
    Linux,
    GNUHurd,
    Solaris,
    AIX,
    IRIX,
    FreeBSD,
    Tru64,
    NovellModesto,
    OpenBSD,
    OpenVMS,
    NonStop,
    AROS,
    FenixOS,
    CloudABI,
}

// Header data is parsed into and available through this struct.
pub struct ElfHeader {
    pub file_size: u64,
    pub elf_type: ElfType,
    pub platform_bits: PlatformBits,
    pub endianness: Endianness,
    pub version: u32,
    pub header_version: u8,
    pub abi: TargetABI, /* usually 0=SystemV regardless of target */
    pub instruction_set: InstructionSet,

    // sizes of the following fields are platform dependent
    pub flags: u32,       /* TODO: not implemented, always 0 */
    pub header_size: u16, /* 64 bytes (64-bit) or 52 bytes (32-bit) */

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
        ElfHeader { file_size: 0,
                    elf_type: ElfType::Unknown,
                    platform_bits: PlatformBits::Unknown,
                    endianness: Endianness::Unknown,
                    version: 0,
                    header_version: 0,
                    abi: TargetABI::NoSpecific,
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
        println!("File size: {:?}", self.file_size);
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

/*
 * Parse the general ELF header (must be done first to determine endianness,
 * platform, and offsets to text and data sections for further parsing). An
 * ELF file header is 64 or 52 bits long, depending on the platform. I.e.
 * the platform must be determined first to then decide how to proceed. It
 * is never necessary to read more than 64 bits into the first buffer.
 *
 * | 32 bit | 64 bit | Field Value                                         |
 * | ------ | ------ | --------------------------------------------------- |
 * | 0-3    | 0-3    | Magic number (0x7F and 'ELF' in ASCII)              |
 * | 4      | 4      | 1 (32 bit) or 2 (64 bit)                            |
 * | 5      | 5      | 1 (little endian) or 2 (big endian)                 |
 * | 6      | 6      | ELF header version                                  |
 * | 7      | 7      | OS ABI (often defaults to 0, independent of OS)     |
 * | 8-15   | 8-15   | Padding                                             |
 * | 16-17  | 16-17  | 1 (reloc.), 2 (exec.), 3 (shared), 4 (core)         |
 * | 18-19  | 18-19  | Instruction set                                     |
 * | 20-23  | 20-23  | ELF Version                                         |
 * | 24-27  | 24-31  | Program entry position                              |
 * | 28-31  | 32-39  | Program header table position                       |
 * | 32-35  | 40-47  | Section header table position                       |
 * | 36-39  | 48-51  | Architecture-dependent flags                        |
 * | 40-41  | 52-53  | Header size                                         |
 * | 42-43  | 54-55  | Size of entry in program header table               |
 * | 44-45  | 56-57  | Number of entries in program header table           |
 * | 46-47  | 58-59  | Size of entry in section header table               |
 * | 48-49  | 60-61  | Number of entries in section header table           |
 * | 50-51  | 62-63  | Index in section header table with section names    |
 * | ------ | ------ | --------------------------------------------------- |
 */
pub fn get_header(mut file: &mut std::fs::File) -> ElfHeader {
    // set up a byte buffer and a default header struct
    let mut buf = [0; ELF_HEADER_LEN];
    let mut offset = 0;
    let mut header: ElfHeader = ElfHeader::new();
    let buf_size = buf.len();

    // read header bytes into buffer and start parsing
    let bytes = read_into_buf(&mut file, &mut buf);
    validate_read(bytes, ELF_HEADER_LEN);
    while offset < buf_size {
        if let Some(inc) = elf_header::parse(&buf, offset, &mut header) {
            offset += inc;
        };
        if let Some(inc) = elf_header_32_bit::parse(&buf, offset, &mut header) {
            offset += inc;
        }
        if let Some(inc) = elf_header_64_bit::parse(&buf, offset, &mut header) {
            offset += inc;
        }
    }

    if super::DEBUG {
        print_buffer(&buf[..]); /* FIXME: will be CLI feature */
    }

    header
}
