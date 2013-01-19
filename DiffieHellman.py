#!/usr/bin/env python
"""
PyDHE - Diffie-Hellman Key Exchange in Python
Copyright (C) 2013 by Mark Loiseau

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


For more information:
http://blog.markloiseau.com/2013/01/diffie-hellman-tutorial-in-python/
"""

from binascii import hexlify
import hashlib

# If a secure random number generator is unavailable, exit with an error.
try:
	import Crypto.Random.random
	secure_random = Crypto.Random.random.getrandbits
except ImportError:
	import OpenSSL
	secure_random = lambda x: long(hexlify(OpenSSL.rand.bytes(x>>3)), 16)


class DiffieHellman(object):
	"""
	A reference implementation of the Diffie-Hellman protocol.
	This class uses the 6144-bit MODP Group (Group 17) from RFC 3526.
	This prime is sufficient to generate an AES 256 key when used with a 540+ bit
	exponent.
	"""

	prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF	
	generator = 2
	
	def __init__(self):
		"""
		Generate the public and private keys.
		"""
		self.privateKey = self.genPrivateKey(576)
		self.publicKey = self.genPublicKey()

	
	def genPrivateKey(self, bits):
		"""
		Generate a private key using a secure random number generator.
		"""
		return secure_random(bits)

	
	def genPublicKey(self):
		"""
		Generate a public key X with g**x % p.
		"""
		return pow(self.generator, self.privateKey, self.prime)


	def checkPublicKey(self, otherKey):
		"""
		Check the other party's public key to make sure it's valid.
		Since a safe prime is used, verify that the Legendre symbol is equal to one.
		"""
		if(otherKey > 2 and otherKey < self.prime - 1):
			if(pow(otherKey, (self.prime - 1)/2, self.prime) == 1):
				return True
		return False

		
	def genSecret(self, privateKey, otherKey):
		"""
		Check to make sure the public key is valid, then combine it with the
		private key to generate a shared secret.
		"""
		if(self.checkPublicKey(otherKey) == True):
			sharedSecret = pow(otherKey, privateKey, self.prime)
			return sharedSecret
		else:
			raise Exception("Invalid public key.")
			
	
	def genKey(self, otherKey):
		"""
		Derive the shared secret, then hash it to obtain the shared key.
		"""
		self.sharedSecret = self.genSecret(self.privateKey, otherKey)
		s = hashlib.sha256()
		s.update(str(self.sharedSecret))
		self.key = s.digest()
		
	def getKey(self):
		"""
		Return the shared secret key
		"""
		return self.key


	def showParams(self):
		"""
		Show the parameters of the Diffie Hellman agreement.
		"""
		print "Parameters:"
		print
		print "Prime: ", self.prime
		print "Generator: ", self.generator
		print "Private key: ", self.privateKey
		print "Public key: ", self.publicKey
		print


	def showResults(self):
		"""
		Show the results of a Diffie-Hellman exchange.
		"""
		print "Results:"
		print
		print "Shared secret: ", self.sharedSecret
		print "Shared key: ", hexlify(self.key)
		print


if __name__=="__main__":
	"""
	Run an example Diffie-Hellman exchange 
	"""
	
	a = DiffieHellman()
	b = DiffieHellman()
	
	a.genKey(b.publicKey)
	b.genKey(a.publicKey)

	if(a.getKey() == b.getKey()):
		print "Shared keys match."
		print "Key:", hexlify(a.key)
	else:
		print "Shared secrets didn't match!"
		print "Shared secret: ", a.genSecret(b.publicKey)
		print "Shared secret: ", b.genSecret(a.publicKey)

