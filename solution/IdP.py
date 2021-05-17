import typing

import cherrypy
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from saml2.samlp import AuthnRequest, authn_request_from_string
from saml2.config import Config
from saml2.server import Server

from queries import setup_database, get_user
from utils import ZKP_IdP


# TODO -> PERGUNTAR SE O IdP É QUE DETERMINA O NÚMERO DE ITERAÇÕES OU SE TÊM DE SER OS DOIS
zkp_values: typing.Dict[str, ZKP_IdP] = {}
NUM_ITERATIONS = 10


class IdP(object):
	@cherrypy.expose
	def login(self, **kwargs):
		saml_request: AuthnRequest = authn_request_from_string(
			OneLogin_Saml2_Utils.decode_base64_and_inflate(kwargs['SAMLRequest']))
		cherrypy.response.cookie['id'] = saml_request.id
		print("ola")
		print(saml_request)
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

		if current_zkp.iteration >= NUM_ITERATIONS*2:
			server = Server("idp")
			entity = server.response_args(current_zkp.saml_request)
			response = server.create_authn_response(identity={'username': current_zkp.username},
			                                        userid=current_zkp.username,
			                                        **entity)
			current_zkp.saml_response = response
		return {
			'nonce': nonce,
			'response': challenge_response
		}

	@cherrypy.expose
	def identity(self, id):
		# TODO -> set up this
		print(zkp_values[id].saml_response)
		# raise cherrypy.HTTPRedirect('/credentials')

	@cherrypy.expose
	def credentials(self, username):
		# TODO -> THIS MUST BE SAML
		raise cherrypy.HTTPRedirect("http://localhost:8081/identity?username=" + username, 307)


if __name__ == '__main__':
	setup_database()
	cherrypy.config.update({'server.socket_host': '127.0.0.1',
	                        'server.socket_port': 8082})
	cherrypy.quickstart(IdP())
