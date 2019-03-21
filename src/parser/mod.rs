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

pub const ELF_HEADER_LEN: u64 = 1;
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
    pub version: u8,
    pub header_version: u8,
    pub abi: u8, /* 0 for System V, maybe others */
    pub instruction_set: InstructionSet,
}

impl ElfHeader {
    // create a new `ElfHeader' struct with default values
    pub fn new() -> ElfHeader {
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
    pub fn print(&self) {
        println!("Platform: {:?}", self.platform_bits);
        println!("Endianness: {:?}", self.endianness);
        println!("ELF version: {:?}", self.version);
        println!("Header version: {:?}", self.header_version);
        println!("Operating System ABI: {:?}", self.abi);
        println!("Type: {:?}", self.elf_type);
        println!("Instruction set: {:?}", self.instruction_set);
    }
}
