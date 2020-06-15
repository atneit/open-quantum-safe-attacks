# Open Quantum Safe Attacks

Proof-Of-Concept attacks against `liboqs` (Open Quantum Safe).

## Implemented attacks:

* FrodoKEM FO-transform timing attack [paper here](https://eprint.iacr.org/2020/xxx) (soon)

## Get the source

You need  `git clone --recursive <url>` in order to also get the submodules.

## How to compile and install dependencies (Linux)

    cd liboqs-rs-bindings
    ./build-oqs.sh
    cd ..

## How to compile the program  (Linux)

You need `rust` installed, if you haven't already, here's how:

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

This program depends a fork of `liboqs` and it must be built separately:

    cd liboqs-rs-bindings/
    bash build-oqs.sh
    cd ..
    
Then it is a simple matter to build the attack-program with

    cargo build --release

## How to run the program

The easiest way to run it is to use the following command (which also (re)builds it, if necessary).
Anything put after "`--`" is arguments to the program, (as opposed to the build system "cargo")

    cargo run --release -- <program arguments>

e.g.

    cargo run --release -- help