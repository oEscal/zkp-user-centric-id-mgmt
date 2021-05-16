import uuid

from cryptography.hazmat.primitives import hashes, hmac


class ZKP(object):
	def __init__(self, password: bytes):
		self.challenges = b''
		self.expected_response = b''
		self.iteration = 0
		self.password = password

	def response(self, challenge: bytes) -> int:
		# TODO -> VERIFICAR COM O PROF SE A RESPOSTA r A UM CHALLENGE PODE SER UM BYTE
		self.challenges += challenge
		self.iteration += 1

		challenge_response = hash_function(self.challenges, self.password)
		return int(challenge_response[self.iteration % len(challenge_response)])

	def create_challenge(self) -> str:
		nonce = str(uuid.uuid4()).encode()
		self.expected_response = self.response(nonce)
		return str(nonce)


class ZKP_IdP(ZKP):
	def __init__(self):
		super().__init__(password=b'')
		self.username = b''


def hash_function(challenges: bytes, password: bytes) -> bytes:
	digest = hmac.HMAC(password, hashes.SHA256())
	digest.update(challenges)
	return digest.finalize()
