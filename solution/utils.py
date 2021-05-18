from os import urandom
import uuid

from cryptography.hazmat.primitives import hashes, hmac
from saml2.samlp import AuthnRequest


class ZKP(object):
	def __init__(self, password: bytes):
		self.challenges = b''
		self.expected_response = -1
		self.iteration = 0
		self.password = password
		self.all_ok = True

	def response(self, challenge: bytes) -> int:
		# TODO -> VERIFICAR COM O PROF SE A RESPOSTA r A UM CHALLENGE PODE SER UM BYTE
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
