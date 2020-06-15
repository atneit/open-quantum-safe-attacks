#!/bin/bash

echo If running debian/ubuntu install dependecies with the following command:
echo sudo apt install cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz
read -p "Press enter to continue"

cd liboqs

mkdir -p build && cd build
cmake -GNinja ..
ninja
