import os
from os import urandom
import uuid

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from saml2.samlp import AuthnRequest


class ZKP(object):
	def __init__(self, password: bytes):
		self.challenges = b''
		self.expected_response = -1
		self.iteration = 0
		self.password = password
		self.all_ok = True

	def response(self, challenge: bytes) -> int:
		if self.all_ok:
			self.challenges += challenge
			self.iteration += 1

			challenge_response = hash_function(self.challenges, self.password)
			challenge_response = bin(int(challenge_response.hex(), base=16)).lstrip('0b')
			return int(challenge_response[self.iteration % len(challenge_response)])
		else:
			print("oopsie")
			return urandom(1)[0]

	def create_challenge(self) -> str:
		nonce = str(uuid.uuid4()).encode()
		self.expected_response = self.response(nonce)
		return nonce.decode()

	def verify_challenge_response(self, response: int):
		if self.all_ok:                 # just to be sure...
			self.all_ok &= response == self.expected_response


class ZKP_IdP(ZKP):
	def __init__(self, saml_request):
		super().__init__(password=b'')
		self.username = b''
		self.saml_request: AuthnRequest = saml_request
		self.saml_response = None


def hash_function(challenges: bytes, password: bytes) -> bytes:
	digest = hmac.HMAC(password, hashes.SHA256())
	digest.update(challenges)
	return digest.finalize()


def asymmetric_hash():
	return hashes.SHA256()


def asymmetric_padding():
	return padding.PSS(
		mgf=padding.MGF1(asymmetric_hash()),
		salt_length=padding.PSS.MAX_LENGTH
	)


def create_directory(directory: str):
	if not os.path.exists(directory):
		os.mkdir(directory)  # 666


def aes_key_derivation(password: bytes, salt: bytes) -> bytes:
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000
	)
	return kdf.derive(password)


def aes_cipher(password: bytes, salt: bytes, iv: bytes) -> Cipher:
	key = aes_key_derivation(password, salt)
	cipher = Cipher(algorithm=algorithms.AES(key=key), mode=modes.CBC(iv))
	return cipher
