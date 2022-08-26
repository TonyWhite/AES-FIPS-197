
# Advanced Encryption Standard (AES)

C++ code implementing the Advanced Encryption Standard (AES) block cipher as specified in the FIPS Publication 197 by the NIST.

## Overview

This code implements the Advanced Encryption Standard (AES) block cipher as described in the original FIPS Publication 197 by the NIST. Hence, only the bare block cipher is implemented. This will be combined with one of the many block modes of operation to obtain a stream cipher.

Note: This implementation does not come with any guarantees.

## References

1. Forked from Jan Mölter's [aes](https://github.com/janmoelter/aes) project.
2. "Announcing the ADVANCED ENCRYPTION STANDARD (AES)". Federal Information Processing Standards Publication 197. United States National Institute of Standards and Technology (NIST). DOI: [10.6028/NIST.FIPS.197](https://doi.org/10.6028/NIST.FIPS.197).

## Test

Launch test in `src` directory

```
./make
```

The executable will be compiled into the `/tmp` folder and will be deleted when it finishes running.

## The goal

Prepare easy-to-use source code for mission critical scenarios.
