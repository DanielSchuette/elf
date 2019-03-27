/*
 * `parser/' contains submodules for parsing the ELF and program headers as
 * well as the data and text sections of an ELF file.
 *
 * Author: Daniel Schuette (d.schuette@online.de)
 * License: MIT (see LICENSE.md at https://github.com/DanielSchuette/elf)
 */
pub mod elf_header;
pub mod prog_header;

use crate::utils::{print_buffer, read_into_buf, validate_read, Config};
use elf_header::{bits_32, bits_64};
use prog_header::parse_segment;
use std::fs::File;
use std::io::Read;

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
    // Create a new `ElfHeader' struct with default values.
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

    // Validate header length.
    pub fn validate(&self) -> bool {
        if self.platform_bits == PlatformBits::Bits64 {
            if self.header_size != 0x40 {
                return false;
            }
        } else if self.platform_bits == PlatformBits::Bits32 {
            if self.header_size != 0x34 {
                return false;
            }
        }
        true
    }

    // Pretty-print struct as a table, mainly for debugging.
    pub fn print(&self) {
        println!("+-----------------------------------------------+---------------+");
        println!("| File size\t\t\t\t\t| {:?}\t\t|", self.file_size);
        println!("| Platform\t\t\t\t\t| {:?}\t|", self.platform_bits);
        println!("| Endianness\t\t\t\t\t| {:?}\t|", self.endianness);
        println!("| ELF version\t\t\t\t\t| {:?}\t\t|", self.version);
        println!("| Header version\t\t\t\t| {:?}\t\t|", self.header_version);
        println!("| Operating System ABI\t\t\t\t| {:?}\t|", self.abi);
        println!("| Type\t\t\t\t\t\t| {:?}\t|", self.elf_type);
        println!("| Instruction set\t\t\t\t| {:?}\t|", self.instruction_set);
        println!("| Flags\t\t\t\t\t\t| {:?}\t\t|", self.flags);
        println!("| Header size\t\t\t\t\t| {:?}\t\t|", self.header_size);
        println!("| Program entry position\t\t\t| {:?}\t|",
                 self.prog_entry_pos);
        println!("| Program header table position\t\t\t| {:?}\t\t|",
                 self.prog_tbl_pos);
        println!("| Section header table position\t\t\t| {:?}\t\t|",
                 self.sec_tbl_pos);
        println!("| Program header entry size\t\t\t| {:?}\t\t|",
                 self.prog_size_hentr);
        println!("| Number of program header entries\t\t| {:?}\t\t|",
                 self.prog_no_hentr);
        println!("| Section header entry size\t\t\t| {:?}\t\t|",
                 self.sec_size_hentr);
        println!("| Number of section header entries\t\t| {:?}\t\t|",
                 self.sec_no_entr);
        println!("| Index of section names in section header\t| {:?}\t\t|",
                 self.sec_tbl_names_pos);
        println!("+-----------------------------------------------+---------------+");
    }
}

/*
 * Parse the general ELF header (must be done first to determine endianness,
 * platform, and offsets to text and data sections for further parsing). An
 * ELF file header is 64 or 52 bits long, depending on the platform. I.e.
 * the platform must be determined first to then decide how to proceed. It
 * is never necessary to read more than 64 bits into the first buffer. A
 * `utils::Config' struct is used to pass around configuration options.
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
pub fn get_elf_header(mut file: &mut File, configs: &Config) -> ElfHeader {
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
        if let Some(inc) = bits_32::parse(&buf, offset, &mut header) {
            offset += inc;
        }
        if let Some(inc) = bits_64::parse(&buf, offset, &mut header) {
            offset += inc;
        }
    }

    if configs.debug_mode {
        print_buffer(&buf[..], "General header buffer");
    }

    header
}

// Program header struct.
#[derive(Debug)]
pub struct ProgHeader {
    entr: Vec<ProgHeadEntry>, /* final size=ElfHeader.prog_no_hentr */
}

#[derive(Debug)]
pub struct ProgHeadEntry {
    s_type: ProgSegmentType,
    flags: ProgHeadFlag,

    d_off: u64,    /* file offset of data for segment */
    v_addr: u64,   /* where to put segment in virtual memory */
    p_addr: u64,   /* physical address, not relevant for System V ABI */
    f_size: u64,   /* size of segment in file */
    mem_size: u64, /* size of segment in memory */
    align: u64,    /* required alignment as a power of 2 */
}

#[derive(Debug)]
pub enum ProgSegmentType {
    /*
     * Loadable   - clear mem_size bytes at v_addr to 0, then copy f_size
     *              bytes from d_off to v_addr
     * InterpInfo - contains a file path to an executable to use as an
     *              interpreter for the following segment
     */
    EntryUnused, /* unused program header table entry, ignore */
    Loadable,    /* loadable segment */
    DynLinkInfo, /* dynamic linking information */
    InterpInfo,  /* interpreter information */
    AuxInfo,     /* auxiliary information */
    Reserved,
    ProgHeader,  /* segment containing a program header table */
    OSReserved,  /* reserved range for operating system, incl. 2 vals */
    CPUReserved, /* reserved range for processor, incl. 2 vals */
}

#[derive(Debug)]
pub enum ProgHeadFlag {
    Executable,
    Writable,
    Readable,
}

impl ProgHeader {
    // Create a new, empty struct.
    pub fn new() -> ProgHeader {
        let entr: Vec<ProgHeadEntry> = vec![];
        ProgHeader { entr }
    }

    // Pretty-print header segments.
    pub fn print(&self) {
        println!("Program header segments:");
        for (i, e) in self.entr.iter().enumerate() {
            println!("No {}: {:#?}", i, e);
        }
    }
}

impl ProgHeadEntry {
    pub fn new() -> ProgHeadEntry {
        ProgHeadEntry { s_type: ProgSegmentType::EntryUnused,
                        flags: ProgHeadFlag::Executable,
                        d_off: 0,
                        v_addr: 0,
                        p_addr: 0,
                        f_size: 0,
                        mem_size: 0,
                        align: 0 }
    }
}

/*
 * A sufficiently populated `ElfHeader' is used to parse the program header
 * segments of an ELF file at `file'. Configuration details are passed via
 * `configs'. A `ProgHeader' has an `entr' field which is a vector of segments.
 *
 *
 * prog_tbl_pos: u64,    /* program header table position */
 * prog_size_hentr: u16, /* size of entry in program header */
 * prog_no_hentr: u16,   /* number of entries in program header */
 */
pub fn get_prog_header(file: &mut File, elf_h: &ElfHeader, _configs: &Config)
                       -> ProgHeader {
    let mut buf: Vec<u8> = vec![];
    file.read_to_end(&mut buf)
        .expect("Failed to read from file");
    let buf = &buf[(elf_h.prog_tbl_pos as usize)..];
    let mut prog_h: ProgHeader = ProgHeader::new();

    for seg in 0..elf_h.prog_no_hentr {
        parse_segment(&buf, &elf_h, &mut prog_h, seg);
    }

    prog_h
}
