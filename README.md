# Open Quantum Safe Attacks

Attacks on liboqs (Open Quantum Safe).

## Get the source

You need  `git clone --recursive <url>` in order to also get the submodules.

## How to compile and install dependencies (Linux)

    cd liboqs-rs-bindings
    ./build-oqs.sh
    cd ..

## How to compile the program  (Linux)

You need `rust` installed:

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Then it is a simple matter to build with

    cargo build

## How to run the program

The easiest way to run it is to use the following command (which also builds it, if neccessary):

    cargo run -- <program arguments>

e.g.

    cargo run -- help