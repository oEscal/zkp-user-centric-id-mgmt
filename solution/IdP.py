import base64
import json
import typing
import uuid
from datetime import datetime, timedelta
from os import urandom

import cherrypy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from saml2.server import Server

from queries import setup_database, get_user, save_user_key, get_user_key
from utils.utils import ZKP_IdP, create_nonce, asymmetric_padding_signature, asymmetric_hash, create_get_url, \
	Cipher_Authentication, \
	asymmetric_upload_derivation_key, asymmetric_padding_encryption

zkp_values: typing.Dict[str, ZKP_IdP] = {}
public_key_values: typing.Dict[str, typing.Tuple[RSAPublicKey, bytes]] = {}
MIN_ITERATIONS_ALLOWED = 300
MAX_ITERATIONS_ALLOWED = 1000
KEYS_TIME_TO_LIVE = 10       # minutes


KEY_PATH_NAME = f"idp_certificate/server.key"


class Asymmetric_IdP(object):
	def __init__(self):
		with open(KEY_PATH_NAME, 'rb') as file:
			pem = file.read()

		self.private_key = load_pem_private_key(
			data=pem,
			password=None,
			backend=default_backend()
		)

	def sign(self, data: bytes) -> bytes:
		return self.private_key.sign(data=data, padding=asymmetric_padding_signature(), algorithm=asymmetric_hash())


class IdP(Asymmetric_IdP):
	def __init__(self, hostname, port):
		super().__init__()

		self.server = Server("idp_conf")
		self.hostname = hostname
		self.port = port

	@staticmethod
	def create_attr_response(zkp: ZKP_IdP):
		response_dict = dict()
		if 'username' in zkp.id_attrs:
			response_dict['username'] = zkp.username
		'''add here more attributes if needed'''

		zkp.response_b64 = base64.urlsafe_b64encode(json.dumps(response_dict).encode())
		zkp.response_signature_b64 = base64.urlsafe_b64encode(zkp.response_b64)

	@cherrypy.expose
	def login(self, id_attrs: str):
		attrs = id_attrs.split(',')
		client_id = str(uuid.uuid4())

		aes_key = urandom(32)
		zkp_values[client_id] = ZKP_IdP(key=aes_key, id_attrs=attrs,
		                                max_iterations=MAX_ITERATIONS_ALLOWED)
		raise cherrypy.HTTPRedirect(create_get_url("http://zkp_helper_app:1080/authenticate",
		                                           params={
			                                           'max_iterations': MAX_ITERATIONS_ALLOWED,
			                                           'min_iterations': MIN_ITERATIONS_ALLOWED,
			                                           'client': client_id,
			                                           'key': base64.urlsafe_b64encode(aes_key)
		                                           }), 307)

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def authenticate(self, **kwargs):
		client_id = kwargs['client']
		current_zkp = zkp_values[client_id]
		request_args = current_zkp.decipher_response(kwargs)

		challenge = request_args['nonce'].encode()
		if current_zkp.iteration < 2:
			if 'username' in request_args:
				username = str(request_args['username'])
				current_zkp.username = username
				current_zkp.password = get_user(username)[0].encode()
			else:
				del current_zkp
				raise cherrypy.HTTPError(400, message='The first request to this endpoint must have the parameter username')
			if 'iterations' in request_args:
				iterations = int(request_args['iterations'])
				if MIN_ITERATIONS_ALLOWED <= iterations <= MAX_ITERATIONS_ALLOWED:
					current_zkp.max_iterations = iterations
				else:
					del current_zkp
					raise cherrypy.HTTPError(406, message='The number of iterations does not met the defined range')
		else:
			current_zkp.verify_challenge_response(int(request_args['response']))

		challenge_response = current_zkp.response(challenge)
		nonce = current_zkp.create_challenge()

		if current_zkp.iteration >= current_zkp.max_iterations*2 and current_zkp.all_ok:
			self.create_attr_response(current_zkp)
		return current_zkp.create_response({
			'nonce': nonce,
			'response': challenge_response
		})

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def authenticate_asymmetric(self, **kwargs):
		client_id = kwargs['client']
		current_zkp = zkp_values[client_id]
		request_args = current_zkp.decipher_response(kwargs)
		if client_id not in public_key_values:
			user_id = request_args['user_id']
			username = request_args['username']
			nonce_received = request_args['nonce'].encode()

			public_key_db = get_user_key(id=user_id, username=username)
			if public_key_db and len(public_key_db) > 0:
				if public_key_db[1] > datetime.now().timestamp():           # verify if the key is not expired
					public_key = load_pem_public_key(data=public_key_db[0].encode(), backend=default_backend())

					# create response to the challenge
					challenge_response = public_key.encrypt(nonce_received, padding=asymmetric_padding_encryption())

					current_zkp.username = username
					nonce = create_nonce()
					public_key_values[client_id] = (public_key, nonce)
					return current_zkp.create_response({
						'nonce': nonce.decode(),
						'response': base64.urlsafe_b64encode(challenge_response).decode()
					})
				else:
					raise cherrypy.HTTPError(410, message="Expired key")
			else:
				raise cherrypy.HTTPError(424, message="No public key for the given user id and username")
		else:
			response = base64.urlsafe_b64decode(request_args['response'])

			public_key, nonce = public_key_values[client_id]
			try:
				public_key.verify(signature=response, data=nonce,
				                  padding=asymmetric_padding_signature(), algorithm=asymmetric_hash())
				self.create_attr_response(current_zkp)
			except InvalidSignature:
				del current_zkp
				del public_key_values[client_id]
				raise cherrypy.HTTPError(401, message="Authentication failed")

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def save_asymmetric(self, **kwargs):
		client_id = kwargs['client']
		current_zkp = zkp_values[client_id]

		key = asymmetric_upload_derivation_key(current_zkp.responses, current_zkp.iteration, 32)
		asymmetric_cipher_auth = Cipher_Authentication(key=key)

		request_args = asymmetric_cipher_auth.decipher_response(current_zkp.decipher_response(kwargs))
		key = request_args['key']
		user_id = str(uuid.uuid4())
		status = False
		if current_zkp.response_b64:
			status = save_user_key(id=user_id, username=current_zkp.username,
			                       key=key,
			                       not_valid_after=(datetime.now() + timedelta(minutes=KEYS_TIME_TO_LIVE)).timestamp())
		return current_zkp.create_response(asymmetric_cipher_auth.create_response({
			'status': status,
			'ttl': KEYS_TIME_TO_LIVE,
			'user_id': user_id
		}))

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def identity(self, **kwargs):
		client_id = kwargs['client']
		current_zkp = zkp_values[client_id]

		response = current_zkp.create_response({
			'response': current_zkp.response_b64.decode(),
			'signature': current_zkp.response_signature_b64.decode()
		})
		del current_zkp

		return response


if __name__ == '__main__':
	setup_database()

	hostname = '127.0.0.1'
	port = 8082
	cherrypy.config.update({'server.socket_host': hostname,
	                        'server.socket_port': port})
	cherrypy.quickstart(IdP(hostname=hostname, port=port))
