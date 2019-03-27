#!/bin/sh
# Convenience script for running different ELF test files.
SUCCESS=false

# make test files
cd data/ && make && cd ../ || exit 1

# run test files
if [ "$1" = '--obj' ]; then
    if [ "$2" = '--b32' ]; then
        cargo run -- --path data/elf_32bit.o
        SUCCESS=true
    elif [ "$2" = '--b64' ]; then
        cargo run -- --path data/elf_64bit.o
        SUCCESS=true
    fi
elif [ "$1" = '--bin' ]; then
    if [ "$2" = '--b32' ]; then
        cargo run -- --path data/elf_32bit
        SUCCESS=true
    elif [ "$2" = '--b64' ]; then
        cargo run -- --path data/elf_64bit
        SUCCESS=true
    fi
fi

# take default action
if [ "$SUCCESS" = 'false' ]; then
    echo 'Running default (64-bit executable file)'
    cargo run -- --path data/elf_64bit
fi

# update dependency graph and clean up `data/'
echo 'Creating updated dependency graph.'
cargo deps | dot -Tpng > assets/deps.png
echo 'Cleaning up.'
cd data/ && make clean && cd ../ || exit 1
exit 0
