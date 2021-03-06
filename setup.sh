#!/bin/bash

apt-get install -y libpcap-dev libssl-dev libboost-chrono-dev libboost-timer-dev cmake

git submodule update --init
cd msgpack-c
git checkout cpp_master

if [ ! -f /usr/local/lib/libtins.so ]; then
  cd /tmp/
  git clone https://github.com/mfontanini/libtins
  cd libtins
  mkdir build
  cd build
  cmake ../ -DLIBTINS_ENABLE_CXX11=1
  make -j$(nproc)
  make install

  cd /tmp/
  rm -rf libtins
fi

ldconfig