import typing

import cherrypy
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from saml2 import create_class_from_xml_string
from saml2.samlp import AuthnRequest

from queries import setup_database, get_user
from utils import ZKP_IdP


zkp_values: typing.Dict[str, ZKP_IdP] = {}


class IdP(object):
	@cherrypy.expose
	def login(self, **kwargs):
		saml_request: AuthnRequest = \
			create_class_from_xml_string(AuthnRequest,
			                             OneLogin_Saml2_Utils.decode_base64_and_inflate(kwargs['SAMLRequest']))
		cherrypy.response.cookie['id'] = saml_request.id
		zkp_values[saml_request.id] = ZKP_IdP()
		raise cherrypy.HTTPRedirect(f"http://zkp_helper_app:1080/authenticate?id={saml_request.id}", 307)

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def authenticate(self, **kwargs):
		id = kwargs['id']
		challenge: bytes = kwargs['nonce'].encode()
		current_zkp = zkp_values[id]
		if 'username' in kwargs:
			current_zkp.username = kwargs['username']
			current_zkp.password = get_user(kwargs['username'])[0].encode()
		challenge_response = current_zkp.response(challenge)
		nonce = current_zkp.create_challenge()

		return {
			'nonce': nonce,
			'response': challenge_response
		}

	@cherrypy.expose
	def identity(self, id):
		# TODO -> set up this
		raise cherrypy.HTTPRedirect('/credentials?username=ola')

	@cherrypy.expose
	def credentials(self, username):
		# TODO -> THIS MUST BE SAML
		raise cherrypy.HTTPRedirect("http://localhost:8081/identity?username=" + username, 307)


if __name__ == '__main__':
	setup_database()
	cherrypy.config.update({'server.socket_host': '127.0.0.1',
	                        'server.socket_port': 8082})
	cherrypy.quickstart(IdP())
