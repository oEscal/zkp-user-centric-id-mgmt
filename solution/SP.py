import typing
from pathlib import Path
import os
import base64
import hashlib

import cherrypy
from mako.template import Template
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.response import OneLogin_Saml2_Response

from utils.utils import create_directory

saml_settings = {
	'idp': {
		'entityId': "http://127.0.0.1:8082",
		'singleSignOnService': {
			'url': "http://127.0.0.1:8082/login",
			'binding': "url:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
		}
	},
	'sp': {
		'entityId': "http://127.0.0.1:8081",
		'assertionConsumerService': {
			'url': "http://127.0.0.1:8081/identity",
			'binding': "url:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
		}
	},
	'strict': False
}


clients_auth: typing.Dict[str, OneLogin_Saml2_Auth] = {}


def dumb_validation(*args):
	return True


OneLogin_Saml2_Response.is_valid = dumb_validation


class SP(object):
	@staticmethod
	def random_name() -> str:
		"""Creates a random name just for temporarility storing an uploded file
		:return:
		"""
		return base64.urlsafe_b64encode(os.urandom(15)).decode('utf8')

	@staticmethod
	def static_page(path: str):
		"""Reads a static HTML page
		:param path:
		:return:
		"""
		return open(f"static/{path}", 'r').read()

	@staticmethod
	def set_cookie(name: str, value: str):
		"""Create a session cookie (insecure, can be forged)
		The validity is short by design, to force authentications
		:param value:
		:param name:
		:return:
		"""
		cookie = cherrypy.response.cookie
		cookie[name] = value
		cookie[name]['path'] = '/'
		cookie[name]['max-age'] = '200'
		cookie[name]['version'] = '1'

	@staticmethod
	def account_contents(account: str) -> str:
		"""Present the account images and an upload form
		:param account:
		:return:
		"""
		contents = '<html><body>'
		contents += '<p>Upload a new image file</p>'
		contents += '<form action="add" method="post" enctype="multipart/form-data">'
		contents += '<input type="file" name="image" /><br>'
		contents += '<input type="submit" value="send" />'
		contents += '</form>'
		contents += '<form action="add" method="post" enctype="multipart/form-data">'
		contents += '<p>List of uploaded image file</sp>'
		contents += '<table border=0><tr>'

		path = f"accounts/{account}"
		files = os.listdir(path)
		count = 0
		for f in files:
			contents += '<td><img src="/img?name=' + f + '"></td>'
			count += 1
			if count % 4 == 0:
				contents += '</tr><tr>'
		contents += '</tr></body></html>'
		return contents

	@staticmethod
	def prepare_auth_parameter(request):
		return {
			'http_host': request.local.name,
			'script_name': request.path_info,
			'server_port': request.local.port,
			'get_data': request.params.copy(),
			'post_data': request.params.copy()
		}

	def get_account(self, redirect):
		"""Checks if the request comes with an account cookie
		This code is unsafe (the cookie can be forged!)
		:param redirect:
		:return:
		"""

		def redirect_to_idp():
			req = self.prepare_auth_parameter(cherrypy.request)
			auth = OneLogin_Saml2_Auth(req, saml_settings)
			login = auth.login()
			login_id = auth.get_last_request_id()
			clients_auth[login_id] = auth
			self.set_cookie('sp_saml_id', login_id)

			raise cherrypy.HTTPRedirect(login, status=307)

		cookies = cherrypy.request.cookie
		# if not cookies:
		if 'sp_saml_id' not in cookies:
			if redirect:
				redirect_to_idp()
			else:
				return False

		saml_id = cookies['sp_saml_id'].value
		if saml_id not in clients_auth or not clients_auth[saml_id].get_attributes():
			if redirect:
				redirect_to_idp()
			else:
				return False

		username = clients_auth[saml_id].get_attributes()['username'][0]
		self.set_cookie('sp_saml_id', saml_id)  # for keeping the session alive
		return username

	@cherrypy.expose
	def index(self):
		"""Root HTTP server method
		:return:
		"""
		account = self.get_account(True)

		create_directory('accounts')
		create_directory(f"accounts/{account}")

		raise cherrypy.HTTPRedirect('/account', status=307)

	@cherrypy.expose
	def login(self) -> str:
		"""Login page, which performs a (visible) HTML redirection
		:return:
		"""
		return self.static_page('login.html')

	@cherrypy.expose
	def identity(self, **kwargs):
		"""Identity provisioning by an IdP
		:param username:
		:return:
		"""
		if cherrypy.request.method == 'POST':
			cookies = cherrypy.request.cookie
			req = self.prepare_auth_parameter(cherrypy.request)
			auth = OneLogin_Saml2_Auth(req, saml_settings)
			auth.process_response()
			errors = auth.get_errors()
			if not errors:
				if auth.is_authenticated():
					clients_auth[cookies['sp_saml_id'].value] = auth
				else:
					print("Not Authenticated")
			else:
				print(f"Error when processing SAML response: {errors}")
		return Template(filename='static/redirect_index.html').render()

	@cherrypy.expose
	def account(self) -> str:
		"""Expose account page
		:return:
		"""
		account = self.get_account(True)
		return self.account_contents(account)

	@cherrypy.expose
	def img(self, name: str):
		"""Get individual account image
		:param name:
		:return:
		"""
		account = self.get_account(True)
		path = f"{os.getcwd()}/accounts/{account}/{name}"
		return cherrypy.lib.static.serve_file(path, content_type='jpg')

	@cherrypy.expose
	def add(self, image):
		"""Upload new image for an account
		:param image:
		:return:
		"""
		name = self.random_name()
		account = self.get_account(False)
		if not account:
			return self.static_page('login.html')

		path = Path(f"{os.getcwd()}/accounts/{account}/{name}")
		m = hashlib.sha1()
		with path.open('wb') as new_file:
			while True:
				data = image.file.read(8192)
				if not data:
					break
				new_file.write(data)
				m.update(data)

		name = base64.urlsafe_b64encode(m.digest()[0:18]).decode('utf8')
		new_path = Path(f"{os.getcwd()}/accounts/{account}/{name}")
		if not new_path.exists():
			path.rename(new_path)
		else:
			path.unlink(missing_ok=True)

		return self.account_contents(account)


if __name__ == '__main__':
	cherrypy.config.update({'server.socket_host': '127.0.0.1',
                            'server.socket_port': 8081})
	cherrypy.quickstart(SP())
