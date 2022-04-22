# Open Quantum Safe Attacks

Proof-Of-Concept attacks against `liboqs` (Open Quantum Safe).

## Implemented attacks:

* FrodoKEM memcmp timing attack. [Paper here](https://eprint.iacr.org/2020/743)
* Rejection Sampling timing attack on BIKE [Paper here](https://eprint.iacr.org/2021/1485)
  * Attack on HQC implemented here: [TODO]()

## Get the source

You need  `git clone --recursive <url>` in order to also get the submodules.


## Dependencies on debian/ubuntu

    sudo apt install cmake gcc ninja-build clang libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz

## How to compile dependency liboqs (Linux)

    cd liboqs-rs-bindings
    ./build-oqs.sh
    cd ..

## How to compile the program  (Linux)

You need nightly version of `rust` installed, if you haven't already, here's how:

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

To install the nighly version of the compiler run the following command:

    rustup toolchain install nightly

To make the nightly version the default for the current directory simply run:

    rustup override set nightly
    
Then it is a simple matter to finally build the program with

    cargo build --release

## How to run the program

The easiest way to run it is to use the following command (which also (re)builds it, if necessary).
Anything put after "`--`" is arguments to the compiled program itself when it runs. Every argument before the
`--` are arguments to the build system `cargo`. `--release`, for example, tells `cargo` that it should build and 
run the optimized non-debug variant (This does not affect the cryptosystems in the `oqs` library though, since it has already been compiled once, with optimization, in the steps above and will not be autmatically rebuilt if the C-sources change)

    cargo run --release -- <program arguments>

e.g.

    cargo run --release -- --help

Of course, if you wish it is also possible to run the binary directly after building: `target/release/oqs-afw help`

## Saved data

In this repo several data files are also stored. These are compressed to save space and download time 
and they are located in the `data/compressed` folder.

If you wish to analyze them with the scripts in the `scripts` folder you must uncompress them first (preferably in the `data/` folder).
