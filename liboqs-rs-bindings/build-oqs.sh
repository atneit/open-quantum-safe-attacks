#!/bin/bash

echo If running debian/ubuntu install dependecies with the following command:
echo sudo apt install autoconf automake libtool gcc libssl-dev python3-pytest unzip xsltproc doxygen graphviz llvm-dev libclang-dev clang
read -p "Press enter to continue"

cd liboqs

autoreconf -i
./configure
make clean
make -j