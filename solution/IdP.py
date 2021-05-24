import base64
import typing
from datetime import datetime, timedelta

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
from utils import ZKP_IdP, create_nonce, asymmetric_padding, asymmetric_hash

# TODO -> PERGUNTAR SE O IdP É QUE DETERMINA O NÚMERO DE ITERAÇÕES OU SE TÊM DE SER OS DOIS
zkp_values: typing.Dict[str, ZKP_IdP] = {}
public_key_values: typing.Dict[str, typing.Tuple[RSAPublicKey, bytes]] = {}
NUM_ITERATIONS = 10
KEYS_TIME_TO_LIVE = 2       # minutes


class IdP(object):
	def __init__(self):
		self.server = Server("idp")

	def create_saml_response(self, zkp: ZKP_IdP):
		entity = self.server.response_args(zkp.saml_request)
		response = self.server.create_authn_response(identity={'username': zkp.username},
		                                             userid=zkp.username, **entity)
		zkp.saml_response = response

	@cherrypy.expose
	def login(self, **kwargs):
		saml_request: AuthnRequest = authn_request_from_string(
			OneLogin_Saml2_Utils.decode_base64_and_inflate(kwargs['SAMLRequest']))
		zkp_values[saml_request.id] = ZKP_IdP(saml_request)
		raise cherrypy.HTTPRedirect(f"http://zkp_helper_app:1080/authenticate?iterations={NUM_ITERATIONS}&id={saml_request.id}", 307)

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def authenticate(self, **kwargs):
		id = kwargs['id']
		challenge: bytes = kwargs['nonce'].encode()
		current_zkp = zkp_values[id]
		if current_zkp.iteration < 2:
			if 'username' in kwargs:
				current_zkp.username = kwargs['username']
				current_zkp.password = get_user(kwargs['username'])[0].encode()
		else:
			current_zkp.verify_challenge_response(int(kwargs['response']))

		challenge_response = current_zkp.response(challenge)
		nonce = current_zkp.create_challenge()

		conf = Config()
		conf.attribute_converters = {'username': [current_zkp.username]}
		conf.entityid = id

		if current_zkp.iteration >= NUM_ITERATIONS*2 and current_zkp.all_ok:
			self.create_saml_response(current_zkp)
		return {
			'nonce': nonce,
			'response': challenge_response
		}

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def authenticate_asymmetric(self, **kwargs):
		saml_id = kwargs['saml_id']
		if saml_id not in public_key_values:
			id = kwargs['id']
			username = kwargs['username']

			public_key_db = get_user_key(id=id, username=username)
			if len(public_key_db) > 0:
				if public_key_db[1] > datetime.now().timestamp():           # verify if the key is not expired
					zkp_values[saml_id].username = username
					nonce = create_nonce()
					public_key = load_pem_public_key(data=public_key_db[0].encode(), backend=default_backend())
					public_key_values[saml_id] = (public_key, nonce)
					return {
						'nonce': nonce.decode()
					}
				else:
					del zkp_values[saml_id]
					raise cherrypy.HTTPError(410, message="Expired key")
			else:
				del zkp_values[saml_id]
				raise cherrypy.HTTPError(424, message="No public key for the given id and username")
		else:
			response = base64.urlsafe_b64decode(kwargs['response'])

			public_key, nonce = public_key_values[saml_id]
			try:
				public_key.verify(signature=response, data=nonce,
			                      padding=asymmetric_padding(), algorithm=asymmetric_hash())
				self.create_saml_response(zkp_values[saml_id])
			except InvalidSignature:
				del zkp_values[saml_id]
				raise cherrypy.HTTPError(401, message="Authentication failed")

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def save_asymmetric(self, id, key):
		current_zkp = zkp_values[id]
		status = False
		if current_zkp.saml_response:
			status = save_user_key(id=id, username=current_zkp.username,
			                       key=key,
			                       not_valid_after=(datetime.now() + timedelta(minutes=KEYS_TIME_TO_LIVE)).timestamp())
		return {
			'status': status,
			'ttl': KEYS_TIME_TO_LIVE
		}

	@cherrypy.expose
	def identity(self, id):
		http_args = \
			http_form_post_message(message=f"{zkp_values[id].saml_response}",
			                      location=f"{zkp_values[id].saml_request.assertion_consumer_service_url}",
			                      typ='SAMLResponse')
		print(dict(http_args)['data'])
		del zkp_values[id]
		return dict(http_args)['data']


if __name__ == '__main__':
	setup_database()
	cherrypy.config.update({'server.socket_host': '127.0.0.1',
	                        'server.socket_port': 8082})
	cherrypy.quickstart(IdP())
