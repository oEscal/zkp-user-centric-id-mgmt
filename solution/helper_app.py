import requests
import uuid

import cherrypy
from mako.template import Template

from utils import ZKP


class HelperApp(object):
	def __init__(self):
		self.iterations = 0

	@staticmethod
	def static_contents(path):
		return open(f"static/{path}", 'r').read()

	@cherrypy.expose
	def index(self):
		raise cherrypy.HTTPRedirect('/authenticate')

	@cherrypy.expose
	def authenticate(self, **kwargs):
		if cherrypy.request.method == 'GET':
			self.iterations = int(kwargs['iterations'])
			print(self.iterations)
			return Template(filename='static/authenticate.html').render(id=kwargs['id'])
		elif cherrypy.request.method == 'POST':
			zkp = ZKP(kwargs['password'].encode())
			data_send = {
				'nonce': '',
				'id': kwargs['id']
			}
			for i in range(self.iterations):
				data_send['nonce'] = zkp.create_challenge()
				response = requests.get(f"http://localhost:8082/authenticate",
				                        params={**data_send,
				                                **({'username': kwargs['username']} if zkp.iteration < 2 else {})})

				# verify if response to challenge is correct
				idp_response = response.json()['response']
				zkp.verify_challenge_response(idp_response)

				# create both response to the IdP challenge and new challenge to the IdP
				challenge: bytes = response.json()['nonce'].encode()
				challenge_response = zkp.response(challenge)
				data_send['response'] = challenge_response
			# after the ZKP
			raise cherrypy.HTTPRedirect(f"http://localhost:8082/identity?id={kwargs['id']}")


if __name__ == '__main__':
	cherrypy.config.update({'server.socket_host': '127.1.2.3',
	                        'server.socket_port': 1080})
	cherrypy.quickstart(HelperApp())
