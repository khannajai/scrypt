This project implements a simple substitution-permutation network
encryption algorithm called scrypt. The algorithm is designed to be
simplistic, so do not use it for anything serious. The purpose of this
project is to get the idea how a substitution-permutation network
works and how modes of operations of block ciphers (like ecb and cbc)
work. 

The API for the scrypt algorithm is defined in the header file
`src/scrypt.h`. Some test cases can be found in
`test/check-scrypt.c`. To build the project, just do:

```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ make test
```