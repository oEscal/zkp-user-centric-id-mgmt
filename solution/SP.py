import typing
from pathlib import Path
import os
import base64
import hashlib

import cherrypy
from mako.template import Template
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from utils.utils import create_directory


COOKIE_TTL = 200            # seconds


saml_settings = {
	'idp': {
		'entityId': "http://127.0.0.1:8082",
		'singleSignOnService': {
			'url': "http://127.0.0.1:8082/login",
			'binding': "url:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
		},
		'x509cert': "MIIDSzCCAjMCFAjkfHTmE6gJanQledaOPjWk5ovpMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlBUMQ8wDQYDVQQIDAZBdmVpcm8xDzANBgNVBAcMBkF2ZWlybzEUMBIGA1UECgwLSWRQIGV4YW1wbGUxDTALBgNVBAsMBEF1dGgxDDAKBgNVBAMMA0lkUDAeFw0yMTA1MzAxNDA2MDFaFw0yMjA1MzAxNDA2MDFaMGIxCzAJBgNVBAYTAlBUMQ8wDQYDVQQIDAZBdmVpcm8xDzANBgNVBAcMBkF2ZWlybzEUMBIGA1UECgwLSWRQIGV4YW1wbGUxDTALBgNVBAsMBEF1dGgxDDAKBgNVBAMMA0lkUDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKHGOTPvhz3UMKpEBC7e3Lj4DGXFqcAzSBscw+S5+fZTfBahCBWK1TpWKfus7tMZ1SZYppiOWaZLEs7cuLqlUXiXl/j+FMzocBNt0HMLAlvz1MYgI1ni8fHVjPmQ0X2GB0fpC1RwgH437fj7UbnIQ6sJoXOJr9uxcfnbL2HuMQQgmuoW5goPiKn/jSZLhIezj7jl/FLr2ii2jJAe6bAjeMebgfoGdoMnN12ULWVXQ7zZCDvNvZM8eceKQkZhiFh/sAKJlGOzLLawz/MCCONYgkTqAuC5QKbi7NMc+ki8N+Pm3cJLwGWaXakyI+WGRzQnrAwOgkn86TgvS0fGhp7lXUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAdBf/Z6FqG8iI1haiF8XoDPpGOmXCP+V0ObuTtVqQzjNGdumjBW8Lq/GamWpCBZI4AjW3C4BK63bZMzsrb5+gh5Iy4sc7Ww79SnZ8RjjZ0HnODGVV5bVhT4xe71ByhwAuWroY/OgmKh5C0aRZidosiioo7vDi0uqdjee0KaDwc0shq1yVGohvyN462zOfygQn0vX2apUoIU/SUpAK76JliL5QoJ7IOjSIecgjJz39BTgNPceFgP4bgtNfFHhohGXRKshS2D9gX/8+La374VHsMgp/TGGTTTnJNwR6YvqTSW6/MCr0klNotFVhPLtlLwHWErv9dx10u5ww7U1x4T5vbw=="
	},
	'sp': {
		'entityId': "http://127.0.0.1:8081",
		'assertionConsumerService': {
			'url': "http://127.0.0.1:8081/identity",
			'binding': "url:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
		},
		'x509cert': "MIIDQzCCAisCFHJXD9V2K23+qZN02NDobafL3bYmMA0GCSqGSIb3DQEBCwUAMF4xCzAJBgNVBAYTAlBUMQ8wDQYDVQQIDAZBdmVpcm8xDzANBgNVBAcMBkF2ZWlybzETMBEGA1UECgwKU1AgZXhhbXBsZTELMAkGA1UECwwCU1AxCzAJBgNVBAMMAlNQMB4XDTIxMDUzMDE1NDgwMloXDTIyMDUzMDE1NDgwMlowXjELMAkGA1UEBhMCUFQxDzANBgNVBAgMBkF2ZWlybzEPMA0GA1UEBwwGQXZlaXJvMRMwEQYDVQQKDApTUCBleGFtcGxlMQswCQYDVQQLDAJTUDELMAkGA1UEAwwCU1AwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtLrPX8cKXqbPxvACqoYCbq/ZtU8pdJUC46m5HT/DosUq2gd9QCKMKCCCU5XqnaZmHXy9i5h/hZjvYbH7RhETp60SixE0T32CAQwdo7ATTONWQN8wubvyvScO84nWfahpQc4KgtjBWwy2iEAJ8MNd5pR3wu1GAn/1jmW+p+tWJipppyA17mupl8R8ZF0eKuGRnhDrokSE5AWudXSfxnyAWF6OFCH3WeIX0yxLnZpaN6EM/USeV7C0mMrb+I82FJtT0rspyasFrQdSdf1z5gpmHqMAYSZ5Kqd2cF3hsmPqrEUXMF9Kv7uM/7H9F0RC+pTtKKDRsJ4HkPFuFi3nw2P9jAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAKTSbnpvAHyfVPdZvWpYobHVD0CiQSp6rUNrZs8xmQKBTTXnIh5FeLzxYiZ3ugm6PNanNez0hx8GyTZmqUehhhEr7PIokdYVoWmPZDab8xazW+qsw8/d0Wy9bQnnT0TZlBzZbMAy3HVkYfKDIFkz0KRCeplx9/ibaP3sMibWSQSr85ORpzGQfMyUmNxlPbs7qi+xjtCDYmYfv0iRMwhGyqhGl0zF60FxoKJ04TbXHAspBTbQBtlqP3/g01HD5v5yC+V3c8/Cad+ymrYB4ypRSVFzFdIceFKkudc4xLCppbh0/vpT8ggoKVQeCGaBr0vBb4i+poDsksLQ2wKWfrnKjqc=",
		'privateKey': "MIIEpAIBAAKCAQEArS6z1/HCl6mz8bwAqqGAm6v2bVPKXSVAuOpuR0/w6LFKtoHfUAijCggglOV6p2mZh18vYuYf4WY72Gx+0YRE6etEosRNE99ggEMHaOwE0zjVkDfMLm78r0nDvOJ1n2oaUHOCoLYwVsMtohACfDDXeaUd8LtRgJ/9Y5lvqfrViYqaacgNe5rqZfEfGRdHirhkZ4Q66JEhOQFrnV0n8Z8gFhejhQh91niF9MsS52aWjehDP1EnlewtJjK2/iPNhSbU9K7KcmrBa0HUnX9c+YKZh6jAGEmeSqndnBd4bJj6qxFFzBfSr+7jP+x/RdEQvqU7Sig0bCeB5DxbhYt58Nj/YwIDAQABAoIBAQCcr2prcAJc8V8q0KvRtTkEnzrfgzXNvEyogQGxZ3RRM0ajhTEj2gyYoO3JiS3FldcgEVBwLECfz71JfC/pI8Ct2vxIP051Ml6+7OYhWZir+fnO94y2XhgkB5seo81Do92W+EsxWGS3uvLoc4+sCQyKtIc4LGH6+8VnfYT3x0e3ncA085ma2lXQdsSsGEUEiLVzjLLIwjVI/ilMk7EZVGM0T/tmoXPedS21c474h07D5/oDSxSsVa2AzygF+Ob4cgUvKtVl0ck/cKV9NH+6GlyhZ99mAnKWhDdKRJDXTCpdoyQnlEk6pJc13vS2voOpRj4+lSrNlyjfZXyvsFIaJccRAoGBANXuMBfwb9IOx5eeb1ngon+NSbAwmyPd29oK7rEM1ubMY5NjpRtPzArXQ34WtJKf2/HQTmVbla04fIoAsP1BXXHbjhPMmoGgWXjYKdvUFPbn1HdZQQ2/qxw1z5zr+pRzXR1SA7GBkoE1uQGTZAaeoW9Cv/sEQ/5Lf8E9d1QUWa+1AoGBAM89J7p8wcNi8kcpkeDqbyuvCTwknCs6cKO4Ld4r+IRFS1/PnJbUCcxH8pVpIHEl4OBGo0GlxbN+iucIlWRzp4xiow4vlmHB1TGL8AgDQDQkLLyrt79mjV71iydB33k/9fuvMLL6XuV4Ydl2NY7uaomdMy62ZdJnwf/HuYIC5/G3AoGAOvS6Yk6LsnsKPFmYXE+Q2NAKJ7kteBPzO8LZhwd/zfkz0/GZFc7G75HlcsE1IFdX2OtMP5iexi8T+0A3hoPWCcO1AvXW+rRDFA+WcZOf929qWT3KtMxGjq6xuZA67WBhn+vzQp7vzhYNF0cUQNLEsJHXsIi7aEBMQ+f5k71L/iUCgYEAjg3SfL9lpkPd5S+2giDQgXYi82n47pzJd0AZmNA1Mp25M/zAzpab/L5Yp1f/V+/p/HIPGEHEiew01HcKyGeKsu0t7dxqzamrNKJCr4ti6Brf25gthPKL90qCzy8VOyy/tXz5+cUrZUomcITZ45bDyn7KBbwbgaWD0ouaOmc5jHMCgYAx/PRhfxMfOPDY5J/4Ku3anoV2XGzGNMpw5TNRELLx8m23kp/g9bglGb0yUBcJ2h5+iIy7HrR2LYLxGUJeDIfp+iCIpybtI/kDBbV6SiAj+ePiZxbJ9RoAhIU/g8gHqlBnIsmedPSEKU+PTmc3PWVmN+mGqFgs8cZXsPzQ4V7N4A=="
	},
	'security': {
		'authnRequestsSigned': True,
	},
	'strict': True
}


clients_auth: typing.Dict[str, OneLogin_Saml2_Auth] = {}


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
		cookie[name]['max-age'] = f"{COOKIE_TTL}"
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
			request_id = cookies['sp_saml_id'].value

			req = self.prepare_auth_parameter(cherrypy.request)
			auth = OneLogin_Saml2_Auth(req, saml_settings)
			auth.process_response(request_id=request_id)
			errors = auth.get_errors()
			if not errors:
				if auth.is_authenticated():
					clients_auth[request_id] = auth
				else:
					print("Not Authenticated")
			else:
				print(f"Error when processing SAML response: {errors}")
				print(f"{auth.get_last_error_reason()}")
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
