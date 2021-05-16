import uuid

import cherrypy
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from saml2 import create_class_from_xml_string
from saml2.samlp import AuthnRequest

from queries import setup_database, get_user
from utils import hash_function

zkp_values = {}


class IdP(object):
	@cherrypy.expose
	def login(self, **kwargs):
		saml_request: AuthnRequest = \
			create_class_from_xml_string(AuthnRequest,
			                             OneLogin_Saml2_Utils.decode_base64_and_inflate(kwargs['SAMLRequest']))
		cherrypy.response.cookie['id'] = saml_request.id
		zkp_values[saml_request.id] = {}
		raise cherrypy.HTTPRedirect(f"http://zkp_helper_app:1080/authenticate?id={saml_request.id}", 307)

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def authenticate(self, **kwargs):
		id = kwargs['id']
		challenge: bytes = kwargs['nonce'].encode()
		print(challenge)
		if 'username' in kwargs:
			zkp_values[id]['username'] = kwargs['username']
			zkp_values[id]['password'] = get_user(kwargs['username'])[0].encode()
			zkp_values[id]['expected_response'] = b''
			zkp_values[id]['challenges'] = b''
			zkp_values[id]['iteration'] = 0
		zkp_values[id]['challenges'] += challenge
		zkp_values[id]['iteration'] += 1

		challenge_response = hash_function(zkp_values[id]['challenges'], zkp_values[id]['password'])
		challenge_response = challenge_response[zkp_values[id]['iteration'] % len(challenge_response)]

		nonce = str(uuid.uuid4()).encode()
		zkp_values[id]['challenges'] += nonce
		zkp_values[id]['iteration'] += 1
		zkp_values[id]['expected_response'] = hash_function(zkp_values[id]['challenges'], zkp_values[id]['password'])
		zkp_values[id]['expected_response'] = zkp_values[id]['expected_response'][zkp_values[id]['iteration'] % len(zkp_values[id]['expected_response'])]

		return {
			'nonce': str(nonce),
			'response': int(challenge_response)
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
