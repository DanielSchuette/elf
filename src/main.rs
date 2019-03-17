/*
 * TEMP_NAME is a command line utility that reads the binary elf format.
 * FIXME: Enable all linter flags before deployment.
 */
#![allow(dead_code)]
#![allow(unused)]
use std::fs;
use std::io::prelude::*;

const BUF_SIZE: usize = 1024;
const ELF_PATH: &str = "../data/elf";
const ELF_HEADER_LEN: u64 = 1;

enum PlatformBits {
    Bits64,
    Bits32,
}

// Header data is parsed into and available through this struct.
struct ElfHeader {
    platform_bits: PlatformBits,
}

fn main() {
    // open elf file and access metadata to verify correct
    // length and file type
    let mut f = fs::File::open(ELF_PATH).expect("Cannot open file");
    let metadata = f.metadata().expect("Cannot read file metadata");
    let file_len = metadata.len();

    if (!metadata.is_file()) || (file_len < ELF_HEADER_LEN) {
        panic!(format!("{} is not a file or empty.", ELF_PATH));
    }

    // read 10 bytes of data at a time from file into `buf'
    let mut buf = [0; BUF_SIZE];
    let mut bytes_read = 0;
    let mut bytes = 1;
    let mut header: ElfHeader;

    while bytes > 0 {
        bytes = read_into_buf(&mut f, &mut buf);

        if bytes_read == 0 {
            let mut bc = 0; /* bytes already consumed */

            while bc < buf.len() {
                match bc {
                    0 => {
                        // every elf file starts with magic number 0x7F
                        if buf[bc] != 0x7F {
                            panic!("Cannot find the magic number");
                        }
                        bc += 1;
                    }
                    _ => {
                        bc += 1;
                    }
                }
            }
        }
        //print_buffer(&buf);
        bytes_read += bytes;
    }
    assert_eq!(
        bytes_read, file_len as usize,
        "Did not read as many bytes as expected."
    );
}

// Read as many bytes from `file' into `buf' as possible. The actual number is
// limited by the length of `buf' and the number of bytes left in `file'. The
// number of bytes read is then returned. This fn panics on errors.
fn read_into_buf(file: &mut fs::File, mut buf: &mut [u8]) -> usize {
    file.read(&mut buf).expect("Cannot read from file")
}

// Print the contents of a byte buffer. For debugging purposes.
fn print_buffer(buf: &[u8]) {
    for byte in buf.iter() {
        if byte.is_ascii_alphabetic() {
            let c = *byte as char;
            if c == ' ' {
                print!("space ");
            } else {
                print!("{} ", c);
            }
        } else {
            print!("{} ", byte);
        }
    }
}
