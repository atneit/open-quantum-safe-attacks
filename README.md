# Open Quantum Safe Attacks

Proof-Of-Concept attacks against `liboqs` (Open Quantum Safe).

## Implemented attacks:

* FrodoKEM memcmp timing attack. [Paper here](https://eprint.iacr.org/2020/743)
* Rejection Sampling timing attack on BIKE [Paper here](https://eprint.iacr.org/2021/1485)
  * Attack on HQC implemented [separately here](https://github.com/hqc-attack/hqc-attack)

## 1. Get the source

You need  `git clone --recursive <url>` in order to also get the submodules.


## 2. Dependencies on debian/ubuntu

    sudo apt install cmake gcc ninja-build clang libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz

## 3. How to compile dependency liboqs (Linux)

    cd liboqs-rs-bindings
    ./build-oqs.sh
    cd ..

## 4. How to install the Rust compiler

You need a proper `rust` environment installed, if you haven't already, here's how:

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
## 5. How to compile the program  (Linux)
    
Then it is a simple matter to finally build the program with

    cargo build --release

## 6. How to run the program

The easiest way to run it is to use the following command (which also (re)builds it, if necessary).
Anything put after "`--`" is arguments to the compiled program itself when it runs. Every argument before the
`--` are arguments to the build system `cargo`. For example, `--release`, tells `cargo` that it should build and run the optimized non-debug variant (This does not affect the cryptosystems in the `oqs` library, since they have already been compiled once, with optimization, in step 3 above and will not be autmatically rebuilt even if the C-sources change)

    cargo run --release -- <program arguments>

e.g.

    cargo run --release -- --help

Of course, if you wish it is also possible to run the binary directly after building: `target/release/oqs-afw --help` or `target/debug/oqs-afw --help`

## 7. Usage instructions

This program is comprised of many different subprogram designed to aid in the development and research of new side-channel attacks against the `liboqs` library.

Most of these commands are of no use for new users but simply remain as a collection of routines that might or might not be usefull in any future endeavors.

The **actually usefull** commands, for new users are documented in the following files:

1. Paper: "A key-recovery timing attack on post-quantum primitives using the Fujisaki-Okamoto transformation and its application on FrodoKEM"
    * Not implemented.
2. Paper: "Don't Reject This: Key-Recovery Timing Attacks Due to Rejection-Sampling in HQC and BIKE"
    * See [visualize-rejection_sampling_key_recovery.ipynb](scripts/visualize-rejection_sampling_key_recovery.ipynb)


