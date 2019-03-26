#!/bin/sh
# Convenience script for running different ELF test files.
SUCCESS=false

# make test files
cd data/ && make && cd ../ || exit 1

# run test files
if [ "$1" = '--obj' ]; then
    if [ "$2" = '--b32' ]; then
        cargo run -- data/elf_32bit.o
        SUCCESS=true
    elif [ "$2" = '--b64' ]; then
        cargo run -- data/elf_64bit.o
        SUCCESS=true
    fi
elif [ "$1" = '--bin' ]; then
    if [ "$2" = '--b32' ]; then
        cargo run -- data/elf_32bit
        SUCCESS=true
    elif [ "$2" = '--b64' ]; then
        cargo run -- data/elf_64bit
        SUCCESS=true
    fi
fi

# take success of failure action
if [ "$SUCCESS" = 'true' ]; then
    cd data/ && make clean && cd ../ || exit 1
    exit 0
else
    echo 'Failed to interpret parameters'
    exit 1
fi
