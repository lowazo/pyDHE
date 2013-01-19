# pyDHE
PyDHE is an implementation of the Diffie-Hellman key exchange protocol in Python. A background tutorial can be found at <http://blog.markloiseau.com/2013/01/diffie-hellman-tutorial-in-python/>.

DiffieHellman.py contains a functional implementation of the protocol, and SimpleDHE.py includes a simplified example of the protocol's steps.

## Disclaimer
PyDHE is provided as a demonstration of the Diffie-Hellman key exchange protocol. Per the GPL, it is provided without any warranty or implication of fitness for a purpose.

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

## Security
The DiffieHellman class uses parameters recommended by [RFC 3562](http://www.rfc-editor.org/rfc/rfc3526.txt) for generation of a 256-bit key, including a 6144-bit MODP prime and an exponent that is at least 540 bits in length.

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