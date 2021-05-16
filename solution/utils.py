from cryptography.hazmat.primitives import hashes, hmac


def hash_function(challenges: bytes, password: bytes) -> bytes:
	digest = hmac.HMAC(password, hashes.SHA256())
	digest.update(challenges)
	return digest.finalize()
