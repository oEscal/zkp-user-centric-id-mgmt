import base64
import json
import os
from os import urandom
import uuid
from requests.models import PreparedRequest

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import padding as padding_asymmetric
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class ZKP(object):
	def __init__(self, password: bytes):
		self.challenges = b''
		self.expected_response = -1
		self.iteration = 0
		self.password = password
		self.all_ok = True
		self.responses = b''

	def response(self, challenge: bytes) -> int:
		if self.all_ok:
			self.challenges += challenge
			self.iteration += 1

			challenge_response = hash_function(self.challenges, self.password)
			self.responses += challenge_response
			challenge_response = bin(int(challenge_response.hex(), base=16)).lstrip('0b')
			return int(challenge_response[self.iteration % len(challenge_response)])
		else:
			print("oopsie")
			return urandom(1)[0]

	def create_challenge(self) -> str:
		nonce = create_nonce()
		self.expected_response = self.response(nonce)
		return nonce.decode()

	def verify_challenge_response(self, response: int):
		if self.all_ok:                 # just to be sure...
			self.all_ok &= response == self.expected_response


class Cipher_Authentication(object):
	def __init__(self, key: bytes):
		self.key = key

		self.block_size = algorithms.AES(self.key).block_size

	def decipher_data(self, data: str, iv: bytes):
		cipher = aes_cipher(key=self.key, iv=iv)

		unpadder = padding.PKCS7(self.block_size).unpadder()
		decrypter = cipher.decryptor()
		decrypted_data = decrypter.update(base64.urlsafe_b64decode(data)) + decrypter.finalize()
		return json.loads(unpadder.update(decrypted_data) + unpadder.finalize())

	def cipher_data(self, data, iv: bytes):
		cipher = aes_cipher(key=self.key, iv=iv)

		padder = padding.PKCS7(self.block_size).padder()
		padded_data = padder.update(json.dumps(data).encode()) + padder.finalize()
		encryptor = cipher.encryptor()
		return base64.urlsafe_b64encode(encryptor.update(padded_data) + encryptor.finalize()).decode()

	def create_response(self, data) -> dict:
		iv = urandom(16)
		return {
			'ciphered': self.cipher_data(data, iv),
			'iv': base64.urlsafe_b64encode(iv).decode()
		}

	def decipher_response(self, response):
		data = response['ciphered']
		iv = base64.urlsafe_b64decode(response['iv'])
		return self.decipher_data(data, iv)


class ZKP_IdP(ZKP, Cipher_Authentication):
	def __init__(self, key: bytes, max_iterations: int):
		ZKP.__init__(self, password=b'')
		Cipher_Authentication.__init__(self, key=key)

		self.username = b''
		self.id_attrs = list()
		self.max_iterations = max_iterations


def create_get_url(url: str, params: dict = None):
	prepare = PreparedRequest()
	prepare.prepare_url(url, params=params if params else {})
	return prepare.url


def overlap_intervals(min1, max1, min2, max2) -> bool:
	return min2 <= min1 <= max2 or min1 <= min2 <= max1


def hash_function(challenges: bytes, password: bytes) -> bytes:
	digest = hmac.HMAC(password, hashes.SHA256())
	digest.update(challenges)
	return digest.finalize()


def create_nonce() -> bytes:
	return str(uuid.uuid4()).encode()


def asymmetric_hash():
	return hashes.SHA256()


def asymmetric_padding_signature():
	return padding_asymmetric.PSS(
		mgf=padding_asymmetric.MGF1(asymmetric_hash()),
		salt_length=padding_asymmetric.PSS.MAX_LENGTH
	)


def asymmetric_padding_encryption():
	return padding_asymmetric.OAEP(
		mgf=padding_asymmetric.MGF1(asymmetric_hash()),
		algorithm=asymmetric_hash(),
		label=None
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


def aes_cipher(key: bytes, iv: bytes) -> Cipher:
	cipher = Cipher(algorithm=algorithms.AES(key=key), mode=modes.CBC(iv))
	return cipher


def asymmetric_upload_derivation_key(responses: bytes, variable: int, size: int) -> bytes:
	result = b''
	for i in range(size):
		result += bytes([responses[(variable*i) % len(responses)]])

	return result
