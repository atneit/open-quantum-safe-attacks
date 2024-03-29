# Open Quantum Safe Attacks

Proof-Of-Concept attacks against `liboqs` (Open Quantum Safe).

## Implemented attacks:

* FrodoKEM memcmp timing attack. [Paper here](https://eprint.iacr.org/2020/743)
* Rejection Sampling timing attack on BIKE [Paper here](https://eprint.iacr.org/2021/1485)
  * Attack on HQC implemented [separately here](https://github.com/hqc-attack/hqc-attack)

## 1. Get the source

You need  `git clone --recursive <url>` in order to also get the submodules.

### 1.1 Note about Git LFS
GIT LFS is used to store some data-files (most notably rejection-sampling-plaintexts.db). Therefore GIT LFS should be installed in order to clone this repository correctly.

If GIT LFS is not installed, these files will be only checked out as (almost) empty text-files. So if you do not care about the pre-generated plaintexts (because you wish to generate your own) then you can continue without GIT LFS.

If you have GIT LFS installed, but still wish to ignore the LFS files you can do this by cloning with the `GIT_LFS_SKIP_SMUDGE=1 git clone --recursive <url>` command

## 2. Dependencies on debian/ubuntu

To install some dependencies, that may or may not be required depending on your usage of this repository, you may execute the following on debian derived linux distributions.

    sudo apt install cmake gcc clang libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz

For other distributions use the corresponding package manager to install at least the `cmake gcc clang libssl-dev` packages. Other packages might also be required.

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
`--` are arguments to the build system `cargo`. For example, `--release`, tells `cargo` that it should build and run the optimized non-debug variant (This does not affect the cryptosystems in the `oqs` library, since they have already been compiled once, with optimization, in step 3 above and will not be automatically rebuilt even if the C-sources change)

    cargo run --release -- <program arguments>

e.g.

    cargo run --release -- --help

Of course, if you wish, it is also possible to run the binary directly after building: e.g. `target/release/oqs-afw --help` or `target/debug/oqs-afw --help`

## 7. Usage instructions

This program is comprised of many different subprograms designed to aid in the development and research of new side-channel attacks against the `liboqs` library.

Most of these commands are of no use for new users but simply remain as a collection of routines that might or might not be useful in any future endeavours.

The **actually useful** commands, for new users are documented in the following files:

1. Paper: "A key-recovery timing attack on post-quantum primitives using the Fujisaki-Okamoto transformation and its application on FrodoKEM"
    * Usage instructions are not written, the reader is mostly on its own for this attack. Though, the most useful command is `cargo run --release -- attack memcmp-frodo-crack-s`. There are also some undocumented files in the `scripts` folder for interpreting the csv output, such as `latency.py` and `violinplot.py`
2. Paper: "Don't Reject This: Key-Recovery Timing Attacks Due to Rejection-Sampling in HQC and BIKE"
    * See [visualize-rejection_sampling_key_recovery.ipynb](scripts/visualize-rejection_sampling_key_recovery.ipynb) for a walkthrough on reproducing the results from the paper. This is a Jupyter Notebook, if you do not have a Jupyter environment to open this file then github's own fileviewer provides a good read-only solution that requires no installation.


### 7.1 Logging and debugging

`oqs-afw` support the following options for debugging and logging purposes. The debug log level is quite verbose and it will slow down the program. The Trace level is **extremely** verbose is is practically useless for most purposes.

    -d, --logdest <logdest>      Additionally write logs to the specified destination
    -l, --loglevel <loglevel>    Set log level to trace, debug, info, warn or error [default: info]