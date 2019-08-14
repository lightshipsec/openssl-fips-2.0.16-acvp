# ACVP Processing for OpenSSL FIPS
This project adds ACVP processing capabilities to OpenSSL by augmenting their existing test harness.
Uses cJSON from https://github.com/DaveGamble/cJSON to handle the JSON parsing.

To compile, modify the tests/Makefile to point at the right cJSON library.

make; 
make build_tests

To use, for example, the AES test harness, with CAVS input, no changes need to be made.
To use the test harness with ACVP input, set an environment variable 'ACVP=1' to indicate
to the harness that you want to use the ACVP stream.

ACVP=1 tests/fips_aesvs -f \<input\> \<output\>

The reason for using environment variables is that we wanted to avoid modifying the
OpenSSL test framework as much as possible.

The code changes to use ACVP are completely encapsulated within the fips/* folder.
For example, the AES ACVP code is found in fips/aes/fips_aesavs.c.
