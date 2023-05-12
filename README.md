# Micro-ECC Tests Solokey

This repository contains the C source code and testing of the added functionalities to the micro-ecc library for my master thesis _Secure & Privacy-Preserving Two-Factor Authentication on a Programmable Security Key_. These functions 
- ```int uECC_scalar_multiplication()```
- ```uECC_addition()```
- ```uECC_calculate_mod_inv()```

will be used on the solokey for a custom extension. 

Uses the [micro-ecc](https://github.com/kmackay/micro-ecc) library by Ken MacKay and [my fork](https://github.com/yasmineantille/micro-ecc) of the repository.

## Checking out the code

``` 
git clone --recurse-submodules https://github.com/yasmineantille/micro-ecc-tests-solokey
```

If you forget the submodules in the clone, you can still get the files with the following commands in the corresponding directory:

```
git submodule init
git submodule update
```


## Compilation Notes

### Prerequisites
Before compiling the project, ensure you have the following prerequisites installed:

- CMake (version 3.22 or higher)
- C compiler (GCC, Clang, or any other compatible compiler)
- CLion IDE (optional but recommended)
 
### Additional Notes
- The micro-ecc library should compile with any C/C++ compiler that supports stdint.h.  
- This project is set up to use CMake as the build system and is designed to be used with [CLion](https://www.jetbrains.com/clion/), an IDE for C and C++ development.
