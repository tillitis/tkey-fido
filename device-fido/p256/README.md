# P-256

This is the C files from 

https://github.com/mpg/p256-m

commit 44af59e0cff5d3b1d653bc333814077ef830e1bd

which is released under [Apache 2.0](LICENSE).

We have added the `p256_keypair_from_bytes()` function, call our own
`rng_generate()` function and made slight changes for build purposes.
