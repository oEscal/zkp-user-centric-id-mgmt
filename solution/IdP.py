import base64

import cherrypy

from onelogin.saml2.utils import OneLogin_Saml2_Utils

from saml2 import create_class_from_xml_string, SamlBase
from saml2.samlp import AuthnRequest


class IdP(object):
	@staticmethod
	def static_contents(path):
		return open(f"static/{path}", 'r').read()

	@cherrypy.expose
	def index(self):
		raise cherrypy.HTTPRedirect('/authenticate', status=307)

	@cherrypy.expose
	def authenticate(self, **kwargs):
		saml_request: AuthnRequest = \
			create_class_from_xml_string(AuthnRequest,
			                             OneLogin_Saml2_Utils.decode_base64_and_inflate(kwargs['SAMLRequest']))
		cherrypy.response.cookie['id'] = saml_request.id
		return cherrypy.HTTPRedirect('zkp_helper_app')

	@cherrypy.expose
	def credentials(self, username):
		raise cherrypy.HTTPRedirect("http://localhost:8081/identity?username=" + username, 307)


cherrypy.config.update({'server.socket_host': '127.0.0.1',
                        'server.socket_port': 8082})
cherrypy.quickstart(IdP())
