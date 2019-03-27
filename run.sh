#!/bin/sh
# Convenience script for running different ELF test files.
SUCCESS=false
fail() {
    echo 'Cargo failed, leaving.'
    exit 1
}


# make test files
cd data/ && make && cd ../ || exit 1

# run test files
if [ "$1" = '--obj' ]; then
    if [ "$2" = '--b32' ]; then
        cargo run -- --debug --path data/elf_32bit.o || fail
        SUCCESS=true
    elif [ "$2" = '--b64' ]; then
        cargo run -- --debug --path data/elf_64bit.o || fail
        SUCCESS=true
    fi
elif [ "$1" = '--bin' ]; then
    if [ "$2" = '--b32' ]; then
        cargo run -- --debug --path data/elf_32bit || fail
        SUCCESS=true
    elif [ "$2" = '--b64' ]; then
        cargo run -- --debug --path data/elf_64bit || fail
        SUCCESS=true
    fi
fi

# take default action
if [ "$SUCCESS" = 'false' ]; then
    echo 'Running default (64-bit executable file)'
    cargo run -- --debug --path data/elf_64bit || fail
fi

# update dependency graph and clean up `data/'
echo 'Creating updated dependency graph.'
cargo deps | dot -Tpng > assets/deps.png
echo 'Cleaning up.'
cd data/ && make clean && cd ../ || exit 1

# I also want to copy the resulting binary to $USER/bin
if [ "$USER" = 'daniel' ]; then
    echo 'Installing binary.'
    cp ./target/debug/elf ~/bin/elf_debug
fi
exit 0
