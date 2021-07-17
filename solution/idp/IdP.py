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

from queries import setup_database, get_user, save_user_key, get_user_key

import sys
sys.path.append('..')
from utils.utils import ZKP_IdP, asymmetric_padding_signature, asymmetric_hash, create_get_url, \
	Cipher_Authentication, \
	asymmetric_upload_derivation_key, asymmetric_padding_encryption


HOST_NAME = '127.0.0.1'
HOST_PORT = 8082
# noinspection HttpUrlsUsage
HOST_URL = f"http://{HOST_NAME}:{HOST_PORT}"

MIN_ITERATIONS_ALLOWED = 300
MAX_ITERATIONS_ALLOWED = 1000
KEYS_TIME_TO_LIVE = 10       # minutes

KEY_PATH_NAME = f"idp_keys/server.key"

zkp_values: typing.Dict[str, ZKP_IdP] = {}


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
	def __init__(self):
		super().__init__()

	@cherrypy.expose
	def login(self):
		client_id = str(uuid.uuid4())

		aes_key = urandom(32)
		zkp_values[client_id] = ZKP_IdP(key=aes_key, max_iterations=MAX_ITERATIONS_ALLOWED)
		raise cherrypy.HTTPRedirect(create_get_url("http://zkp_helper_app:1080/authenticate",
		                                           params={
			                                           'max_iterations': MAX_ITERATIONS_ALLOWED,
			                                           'min_iterations': MIN_ITERATIONS_ALLOWED,
			                                           'client': client_id,
			                                           'key': base64.urlsafe_b64encode(aes_key),
			                                           'auth_url': f"{HOST_URL}/{self.authenticate.__name__}",
			                                           'save_pk_url': f"{HOST_URL}/{self.save_asymmetric.__name__}",
			                                           'id_url': f"{HOST_URL}/{self.identification.__name__}"
		                                           }), 307)

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def authenticate(self, **kwargs):
		client_id = kwargs['client']
		current_zkp = zkp_values[client_id]
		request_args = current_zkp.decipher_response(kwargs)

		# restart zkp
		if 'restart' in request_args and request_args['restart']:
			zkp_values[client_id] = ZKP_IdP(key=current_zkp.key, max_iterations=MAX_ITERATIONS_ALLOWED)
			current_zkp = zkp_values[client_id]

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

		return current_zkp.create_response({
			'nonce': nonce,
			'response': challenge_response
		})

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def save_asymmetric(self, **kwargs):
		client_id = kwargs['client']
		current_zkp = zkp_values[client_id]

		if current_zkp.iteration >= current_zkp.max_iterations * 2 and current_zkp.all_ok:
			key = asymmetric_upload_derivation_key(current_zkp.responses, current_zkp.iteration, 32)
			asymmetric_cipher_auth = Cipher_Authentication(key=key)

			request_args = asymmetric_cipher_auth.decipher_response(current_zkp.decipher_response(kwargs))
			key = request_args['key']
			user_id = str(uuid.uuid4())
			status = save_user_key(id=user_id, username=current_zkp.username,
			                       key=key,
			                       not_valid_after=(datetime.now() + timedelta(minutes=KEYS_TIME_TO_LIVE)).timestamp())
			return current_zkp.create_response(asymmetric_cipher_auth.create_response({
				'status': status,
				'ttl': KEYS_TIME_TO_LIVE,
				'user_id': user_id
			}))
		else:
			raise cherrypy.HTTPError(401, message="ZKP protocol was not completed")

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def identification(self, **kwargs):
		client_id = kwargs['client']
		current_zkp = zkp_values[client_id]
		request_args = current_zkp.decipher_response(kwargs)

		user_id = request_args['user_id']
		username = request_args['username']
		id_attrs_b64 = request_args['id_attrs'].encode()
		id_attrs_signature_b64 = base64.urlsafe_b64decode(request_args['signature'])

		public_key_db = get_user_key(id=user_id, username=username)
		if public_key_db and len(public_key_db) > 0:
			if public_key_db[1] > datetime.now().timestamp():  # verify if the key is not expired
				public_key = load_pem_public_key(data=public_key_db[0].encode(), backend=default_backend())

				# verify if the signature is valid
				try:
					public_key.verify(signature=id_attrs_signature_b64, data=id_attrs_b64,
				                      padding=asymmetric_padding_signature(), algorithm=asymmetric_hash())
				except InvalidSignature:
					del current_zkp
					raise cherrypy.HTTPError(401, message="Authentication failed")

				id_attrs = json.loads(base64.urlsafe_b64decode(id_attrs_b64))

				response_dict = dict()
				if 'username' in id_attrs:
					response_dict['username'] = username
				'''add here more attributes if needed'''

				response_b64 = base64.urlsafe_b64encode(json.dumps(response_dict).encode())
				response_signature_b64 = base64.urlsafe_b64encode(self.sign(response_b64))

				aes_key = urandom(32)
				iv = urandom(16)
				new_cipher = Cipher_Authentication(aes_key)
				ciphered_aes_key = base64.urlsafe_b64encode(public_key.encrypt(
					aes_key, padding=asymmetric_padding_encryption()
				))
				response = new_cipher.cipher_data({
						'response': response_b64.decode(),
						'signature': response_signature_b64.decode()
					},
					iv=iv)

				return current_zkp.create_response({
					'ciphered_aes_key': ciphered_aes_key.decode(),
					'iv': base64.urlsafe_b64encode(iv).decode(),
					'response': response
				})
			else:
				raise cherrypy.HTTPError(410, message="Expired key")
		else:
			raise cherrypy.HTTPError(424, message="No public key for the given user id and username")


if __name__ == '__main__':
	setup_database()

	cherrypy.config.update({'server.socket_host': HOST_NAME,
	                        'server.socket_port': HOST_PORT})
	cherrypy.quickstart(IdP())
