# Public Key Encryption Padding Oracle 

## Background

Bleichenbacher’s 1998 paper outlines how to perform a chosen ciphertext attack on messages using RSA encryption. His attack relies on messages using the PKCS #1 v1.5 padding scheme, and the server working as an ‘oracle’ that reports when messages are incorrectly padded to the user.

This project emulates a server that encodes a PKCS #1 v1.5 compliant message, “This is an encrypted message!”, using a 128 bit key. The ‘Hacker’ class receives the encrypted message and public key, and then proceeds with the attack following the steps outlined in Bleichenbacher’s paper. 

## How to Run

`python rsa_oracle.py`

Lines 8-18 house the RSA compliant key, that can be altered to use any RSA compliant modulus and exponent.
Line 38 defines the message to be encrypted in bytes, and can be changed to any message with bit length shorter than the keysize - 3.
