import base64
import typing
from datetime import datetime, timedelta
from os import urandom

import cherrypy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from saml2.pack import http_form_post_message
from saml2.samlp import AuthnRequest, authn_request_from_string
from saml2.config import Config
from saml2.server import Server

from queries import setup_database, get_user, save_user_key, get_user_key
from utils.utils import ZKP_IdP, create_nonce, asymmetric_padding_signature, asymmetric_hash, create_get_url, \
	Cipher_Authentication, \
	asymmetric_upload_derivation_variable_based, asymmetric_padding_encryption

zkp_values: typing.Dict[str, ZKP_IdP] = {}
public_key_values: typing.Dict[str, typing.Tuple[RSAPublicKey, bytes]] = {}
MAX_ITERATIONS_ALLOWED = 30
MIN_ITERATIONS_ALLOWED = 10
KEYS_TIME_TO_LIVE = 10       # minutes


class IdP(object):
	def __init__(self, hostname, port):
		self.server = Server("idp")
		self.hostname = hostname
		self.port = port

	def create_saml_response(self, zkp: ZKP_IdP):
		entity = self.server.response_args(zkp.saml_request)
		response = self.server.create_authn_response(identity={'username': zkp.username},
		                                             userid=zkp.username, **entity)
		zkp.saml_response = response

	@cherrypy.expose
	def login(self, **kwargs):
		saml_request: AuthnRequest = authn_request_from_string(
			OneLogin_Saml2_Utils.decode_base64_and_inflate(kwargs['SAMLRequest']))

		aes_key = urandom(32)
		zkp_values[saml_request.id] = ZKP_IdP(key=aes_key, saml_request=saml_request,
		                                      max_iterations=MAX_ITERATIONS_ALLOWED)
		raise cherrypy.HTTPRedirect(create_get_url("http://zkp_helper_app:1080/authenticate",
		                                           params={
			                                           'max_iterations': MAX_ITERATIONS_ALLOWED,
			                                           'min_iterations': MIN_ITERATIONS_ALLOWED,
			                                           'id': saml_request.id,
			                                           'key': base64.urlsafe_b64encode(aes_key),
			                                           'idp': base64.urlsafe_b64encode(
				                                           f"http://{self.hostname}:{self.port}".encode())
		                                           }), 307)

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def authenticate(self, **kwargs):
		id = kwargs['id']
		current_zkp = zkp_values[id]
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

		conf = Config()
		conf.attribute_converters = {'username': [current_zkp.username]}
		conf.entityid = id

		if current_zkp.iteration >= current_zkp.max_iterations*2 and current_zkp.all_ok:
			self.create_saml_response(current_zkp)
		return current_zkp.create_response({
			'nonce': nonce,
			'response': challenge_response
		})

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def authenticate_asymmetric(self, **kwargs):
		saml_id = kwargs['saml_id']
		current_zkp = zkp_values[saml_id]
		request_args = current_zkp.decipher_response(kwargs)
		if saml_id not in public_key_values:
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
					public_key_values[saml_id] = (public_key, nonce)
					return current_zkp.create_response({
						'nonce': nonce.decode(),
						'response': base64.urlsafe_b64encode(challenge_response).decode()
					})
				else:
					raise cherrypy.HTTPError(410, message="Expired key")
			else:
				raise cherrypy.HTTPError(424, message="No public key for the given id and username")
		else:
			response = base64.urlsafe_b64decode(request_args['response'])

			public_key, nonce = public_key_values[saml_id]
			try:
				public_key.verify(signature=response, data=nonce,
				                  padding=asymmetric_padding_signature(), algorithm=asymmetric_hash())
				self.create_saml_response(current_zkp)
			except InvalidSignature:
				del current_zkp
				del public_key_values[saml_id]
				raise cherrypy.HTTPError(401, message="Authentication failed")

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def save_asymmetric(self, **kwargs):
		saml_id = kwargs['saml_id']
		current_zkp = zkp_values[saml_id]

		key = asymmetric_upload_derivation_variable_based(current_zkp.responses, current_zkp.iteration, 32)
		asymmetric_cipher_auth = Cipher_Authentication(key=key)

		request_args = asymmetric_cipher_auth.decipher_response(current_zkp.decipher_response(kwargs))
		key = request_args['key']
		user_id = request_args['user_id']
		status = False
		if current_zkp.saml_response:
			status = save_user_key(id=user_id, username=current_zkp.username,
			                       key=key,
			                       not_valid_after=(datetime.now() + timedelta(minutes=KEYS_TIME_TO_LIVE)).timestamp())
		return current_zkp.create_response(asymmetric_cipher_auth.create_response({
			'status': status,
			'ttl': KEYS_TIME_TO_LIVE
		}))

	@cherrypy.expose
	def identity(self, **kwargs):
		id = kwargs['id']
		http_args = \
			http_form_post_message(message=f"{zkp_values[id].saml_response}",
			                      location=f"{zkp_values[id].saml_request.assertion_consumer_service_url}",
			                      typ='SAMLResponse')
		print(dict(http_args)['data'])
		del zkp_values[id]
		return dict(http_args)['data']


if __name__ == '__main__':
	setup_database()

	hostname = '127.0.0.1'
	port = 8082
	cherrypy.config.update({'server.socket_host': hostname,
	                        'server.socket_port': port})
	cherrypy.quickstart(IdP(hostname=hostname, port=port))
