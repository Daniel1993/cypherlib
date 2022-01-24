# CYPHERLIB

In this library I gathered some cryptografic algorithms that can be compiled with a C11 compatible compiler (pure C, no C++).

Most of the code came from the links/repos below:

WELL RNG: http://www.iro.umontreal.ca/~panneton/WELLRNG.html  
SHA3: https://github.com/JamisHoo/Cryptographic-Algorithms  
AES256: http://www.literatecode.com/aes256  
ECC: https://github.com/kmackay/micro-ecc  

## Usage

Bind the algorithms with `cyp_*_bind_<algo_name>` (thread local), then use the interface in `include/cypher.h`. Check `./tests/main.c` for examples of usage.