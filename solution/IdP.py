import cherrypy
import sqlite3
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from saml2 import create_class_from_xml_string
from saml2.samlp import AuthnRequest


DB_NAME = 'idp.db'


class IdP(object):
	@cherrypy.expose
	def login(self, **kwargs):
		saml_request: AuthnRequest = \
			create_class_from_xml_string(AuthnRequest,
			                             OneLogin_Saml2_Utils.decode_base64_and_inflate(kwargs['SAMLRequest']))
		cherrypy.response.cookie['id'] = saml_request.id
		raise cherrypy.HTTPRedirect(f"http://zkp_helper_app:1080/authenticate?id={saml_request.id}", 307)


	@cherrypy.expose
	def identity(self, id):
		# TODO -> set up this
		raise cherrypy.HTTPRedirect('/credentials?username=ola')

	@cherrypy.expose
	def credentials(self, username):
		# TODO -> THIS MUST BE SAML
		raise cherrypy.HTTPRedirect("http://localhost:8081/identity?username=" + username, 307)


if __name__ == '__main__':
	cherrypy.config.update({'server.socket_host': '127.0.0.1',
                        'server.socket_port': 8082})
	cherrypy.quickstart(IdP())
