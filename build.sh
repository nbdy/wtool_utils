#!/bin/bash

if [ ! -d build ]; then mkdir build; cd build; else cd build; fi
cmake ..
make -j$(nproc)
sudo make install

