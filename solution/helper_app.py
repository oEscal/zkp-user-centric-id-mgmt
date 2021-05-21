import requests

import cherrypy
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from mako.template import Template

from utils import ZKP, asymmetric_padding, asymmetric_hash


class Asymmetric_authentication(object):
	def __init__(self):
		self.private_key: RSAPrivateKey = None
		self.public_key: RSAPublicKey = None

		self.load_keys()

	def generate_keys(self):
		self.private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048
		)
		pem = self.private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.BestAvailableEncryption(password=b'olaadeus')
		)

		self.public_key = self.private_key.public_key()
		print(self.private_key.sign(b'ola', asymmetric_padding(), asymmetric_hash()))

		with open('ola.pem', 'wb') as file:
			file.write(pem)

	def load_keys(self):
		try:
			with open('ola.pem', 'rb') as file:
				pem = file.read()
			self.private_key = load_pem_private_key(
				data=pem,
				password=b'olaadeus',
				backend=default_backend()
			)
			self.public_key = self.private_key.public_key()
			# print(self.public_key.verify(b'ola'))
			# self.public_key.verify(ola, b'ola', padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
		except Exception as e:
			print(f"Error: {e}")


class HelperApp(object):
	def __init__(self):
		self.iterations = 0

	@staticmethod
	def static_contents(path):
		return open(f"static/{path}", 'r').read()

	@cherrypy.expose
	def index(self):
		raise cherrypy.HTTPRedirect('/authenticate')

	@cherrypy.expose
	def authenticate(self, **kwargs):
		if cherrypy.request.method == 'GET':
			self.iterations = int(kwargs['iterations'])
			print(self.iterations)
			return Template(filename='static/authenticate.html').render(id=kwargs['id'])
		elif cherrypy.request.method == 'POST':
			asymmetric_authentication = Asymmetric_authentication()
			if asymmetric_authentication.private_key:
				pass
			else:
				zkp = ZKP(kwargs['password'].encode())
				data_send = {
					'nonce': '',
					'id': kwargs['id']
				}
				for i in range(self.iterations):
					data_send['nonce'] = zkp.create_challenge()
					response = requests.get(f"http://localhost:8082/authenticate",
					                        params={**data_send,
					                                **({'username': kwargs['username']} if zkp.iteration < 2 else {})})

					# verify if response to challenge is correct
					idp_response = response.json()['response']
					zkp.verify_challenge_response(idp_response)

					# create both response to the IdP challenge and new challenge to the IdP
					challenge: bytes = response.json()['nonce'].encode()
					challenge_response = zkp.response(challenge)
					data_send['response'] = challenge_response

				# generate asymmetric keys
				asymmetric_authentication.generate_keys()

				# after the ZKP
				raise cherrypy.HTTPRedirect(f"http://localhost:8082/identity?id={kwargs['id']}")


if __name__ == '__main__':
	cherrypy.config.update({'server.socket_host': '127.1.2.3',
	                        'server.socket_port': 1080})
	cherrypy.quickstart(HelperApp())
