#!/usr/bin/env python
"""
A simple Diffie-Hellman example in python
"""

from random import getrandbits

g = 2
prime = 7919
bits = 32

# Generate Alice's secret and public keys (a,A)
a = getrandbits(bits)
A = pow(g, a, prime)

# Generate Bob's secret and public keys (b,B)
b = getrandbits(bits)
B = pow(g, b, prime)

# Generate the shared secrets
s1 = pow(A, b, prime)
s2 = pow(B, a, prime)

if(s1 == s2):
    print("Shared secrets match: ", s1)
