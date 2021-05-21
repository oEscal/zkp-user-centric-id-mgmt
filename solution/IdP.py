import typing

import cherrypy
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from saml2.pack import http_form_post_message
from saml2.samlp import AuthnRequest, authn_request_from_string
from saml2.config import Config
from saml2.server import Server

from queries import setup_database, get_user, save_user_key
from utils import ZKP_IdP


# TODO -> PERGUNTAR SE O IdP É QUE DETERMINA O NÚMERO DE ITERAÇÕES OU SE TÊM DE SER OS DOIS
zkp_values: typing.Dict[str, ZKP_IdP] = {}
NUM_ITERATIONS = 10


class IdP(object):
	def __init__(self):
		self.server = Server("idp")

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
			entity = self.server.response_args(current_zkp.saml_request)
			response = self.server.create_authn_response(identity={'username': current_zkp.username},
			                                             userid=current_zkp.username,
			                                             **entity)
			current_zkp.saml_response = response
		return {
			'nonce': nonce,
			'response': challenge_response
		}

	@cherrypy.expose
	def save_asymmetric(self, id, key):
		current_zkp = zkp_values[id]
		if current_zkp.saml_response:
			save_user_key(id=id, username=current_zkp.username, key=key)


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
