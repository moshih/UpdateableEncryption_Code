This code accompanies our paper "Improving Speed and Security in Updatable Encryption Schemes" (https://eprint.iacr.org/2020/222)

#### Usage
There are 3 main folders. The utils folder contains commonly used functions from third party code. The nested_aes folder contains the code for the updated authenticated encryption based on nested authenticated encryption using AES GCM. The lwe folder contains implementations of updated authenticated encryption based on an almost key-homomorphic PRF (KH-PRF) built from the RLWE problem. There are 4 subfolders (28, 60, 120, and 128) denoting the number of bits for the modulus.

Each of these five folders (one AES and 4 LWE) folders contains a test file (test_aes_nested.c for AES and UAE_<size>.c for LWE, where size is 28, 60, 120 or 128). In these files you may modify size, runs, and total_re_encrypts. The size variable is the size of the message in bytes, runs is how many times to run the test, and total_re_encrypts is the number of re_encrypts to be done.

#### Important Warning

DO NOT USE THIS SOFTWARE TO SECURE ANY SORT OF
REAL-WORLD COMMUNICATIONS!

This software is for performance testing ONLY!
It is full of security vulnerabilities that could
be exploited in any real-world deployment.

The purpose of this software is to evaluate
the performance of the system, NOT to be
used in a deployment scenario.