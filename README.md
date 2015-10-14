# pyDHE
PyDHE is an instructional implementation of the Diffie-Hellman key exchange protocol in Python.

DiffieHellman.py contains a functional implementation of the protocol, and SimpleDHE.py includes a simplified example of the protocol's steps.

## Disclaimer
PyDHE is provided as a demonstration of the Diffie-Hellman key exchange protocol. Per the GPL, it is provided without any warranty or implication of fitness for a purpose.

**WARNING:** The code in this project is for instructional purposes only. No matter how smart you might think you are, it's unwise to use homebrew encryption code in sensitive or production environments.

If you need real security, use an established, audited and thoroughly tested encryption package like PolarSSL, GNUTLS or NaCl. Many established encryption libraries include python bindings.

## Example
The following code performs a complete exchange, including key generation using SHA-256:

```python
a = DiffieHellman()
b = DiffieHellman()

a.genKey(b.publicKey)
b.genKey(a.publicKey)

if(a.getKey() == b.getKey()):
	print "Shared keys match."
	print "Key:", hexlify(a.key)

```

## Specifying your own parameters
To specify a different generator, prime group or private key size, specify them when calling DiffieHellman():

```python
 DiffieHellman(generator=2, group=17, keyLength=540)

```
The class initializer does some *basic* sanity checks on supplied values.

## Security
The DiffieHellman class uses parameters recommended by [RFC 3562](http://www.rfc-editor.org/rfc/rfc3526.txt) for generation of a 256-bit key. Check the spec for other key sizes and options.

## License
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
