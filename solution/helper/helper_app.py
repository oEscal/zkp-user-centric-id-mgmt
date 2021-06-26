import base64
import json
import random

import cherrypy
import requests
from mako.template import Template

import sys

sys.path.append('..')
from utils.utils import ZKP, overlap_intervals, \
	Cipher_Authentication, asymmetric_upload_derivation_key, create_get_url
from managers import Master_Password_Manager, Password_Manager

MIN_ITERATIONS_ALLOWED = 200
MAX_ITERATIONS_ALLOWED = 500


class HelperApp(object):
	def __init__(self):
		self.zkp: ZKP = None

		self.iterations = 0

		self.idp = ''
		self.sp = ''
		self.id_attrs = []
		self.consumer_url = ''
		self.sso_url = ''
		self.auth_url = ''
		self.save_pk_url = ''
		self.id_url = ''

		self.idp_client = ''
		self.sp_client = ''

		self.cipher_auth: Cipher_Authentication = None
		self.password_manager: Password_Manager = None

		self.response_attrs_b64 = ''
		self.response_signature_b64 = ''

	@staticmethod
	def static_contents(path):
		return open(f"static/{path}", 'r').read()

	@cherrypy.expose
	def index(self):
		raise cherrypy.HTTPRedirect('/register')

	@cherrypy.expose
	def error(self, error_id: str):
		errors = {
			'asymmetric_challenge': "The response to the challenge sent to the IdP to authentication with "
			                        "asymmetric keys is not valid. A possible cause for this is the IdP we "
			                        "are contacting is not a trusted one!",
			'zkp_idp_error': "Received error from IdP!",
			'idp_iterations': "The range of allowed iterations received from the IdP is incompatible with the range "
			                  "allowed by the local app. A possible cause for this is the IdP we are contacting is not "
			                  "a trusted one!",
			'zkp_auth_error': "There was an error on ZKP authentication. This could mean that or the introduced "
			                  "password is incorrect, or the IdP we are contacting is not a trusted one!",
			'zkp_save_keys': "There was an error on IdP saving the public keys. This could mean that there was an "
			                 "unexpected error on the ZKP protocol!",
			'zkp_inf_cycle': "The ZKP was already executed one time previously, which means that there was some error "
			                 "on the identification process!",
			'asy_error_decrypt': "There was an error decrypting the data received from the IdP. A possible cause for "
			                     "this is the IdP we are contacting is not a trusted one!"
		}
		return Template(filename='static/error.html').render(message=errors[error_id])

	@cherrypy.expose
	def login(self, sp: str, idp: str, id_attrs: str, consumer_url: str, sso_url: str, client: str):
		self.__init__()
		attrs = id_attrs.split(',')
		return Template(filename='static/login_attributes.html').render(sp=sp, idp=idp, id_attrs=attrs, sso_url=sso_url,
		                                                                consumer_url=consumer_url, client=client)

	@cherrypy.expose
	def authorize_attr_request(self, sp: str, idp: str, id_attrs: list, consumer_url: str, sso_url: str, client: str,
	                           **kwargs):
		if 'deny' in kwargs:
			return Template(filename='static/auth_refused.html').render()
		elif 'allow' in kwargs:
			self.sp = sp
			self.idp = idp
			self.id_attrs = [e for e in id_attrs if e]
			self.consumer_url = consumer_url
			self.sso_url = sso_url
			self.sp_client = client

			raise cherrypy.HTTPRedirect(self.sso_url, status=303)

	def asymmetric_identification(self):
		id_attrs_b64 = base64.urlsafe_b64encode(json.dumps(self.id_attrs).encode())
		id_attrs_signature_b64 = base64.urlsafe_b64encode(self.password_manager.sign(id_attrs_b64))

		ciphered_params = self.cipher_auth.create_response({
			'user_id': self.password_manager.user_id,
			'id_attrs': id_attrs_b64.decode(),
			'signature': id_attrs_signature_b64.decode(),
			'username': self.password_manager.username
		})
		response = requests.get(self.id_url,
		                        params={
			                        'client': self.idp_client,
			                        **ciphered_params
		                        })
		if response.status_code != 200:
			print(f"Error status: {response.status_code}")
			self.zkp_auth()
		else:
			response_dict = self.cipher_auth.decipher_response(response.json())
			try:
				aes_key = self.password_manager.decrypt(base64.urlsafe_b64decode(response_dict['ciphered_aes_key']))
			except Exception as e:
				print(f"Error in function <{self.asymmetric_identification.__name__}>: <{e}>")
				raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
				                                           params={'error_id': 'asy_error_decrypt'}), 301)

			iv = base64.urlsafe_b64decode(response_dict['iv'])
			new_cipher = Cipher_Authentication(aes_key)

			response_dict_attrs = new_cipher.decipher_data(
				data=response_dict['response'],
				iv=iv
			)
			self.response_attrs_b64 = response_dict_attrs['response']
			self.response_signature_b64 = response_dict_attrs['signature']

		raise cherrypy.HTTPRedirect("/attribute_presentation", 303)

	def zkp_auth(self):
		# verify if zkp was already done previously
		if self.zkp is not None:
			raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
			                                           params={'error_id': 'zkp_inf_cycle'}), 301)

		self.zkp = ZKP(self.password_manager.password)
		data_send = {
			'nonce': '',
		}
		for i in range(self.iterations):
			data_send['nonce'] = self.zkp.create_challenge()
			ciphered_params = self.cipher_auth.create_response({
				**data_send,
				**({
					   'username': self.password_manager.username,
					   'iterations': self.iterations
				   } if self.zkp.iteration < 2 else {})
			})
			response = requests.get(self.auth_url, params={
				'client': self.idp_client,
				**ciphered_params
			})

			if response.status_code == 200:
				# verify if response to challenge is correct
				response_dict = self.cipher_auth.decipher_response(response.json())
				idp_response = int(response_dict['response'])
				self.zkp.verify_challenge_response(idp_response)

				# create both response to the IdP challenge and new challenge to the IdP
				challenge = response_dict['nonce'].encode()
				challenge_response = self.zkp.response(challenge)
				data_send['response'] = challenge_response
			else:
				print(f"Error received from idp: <{response.status_code}: {response.reason}>")
				raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
				                                           params={'error_id': 'zkp_idp_error'}), 301)

		if self.zkp.all_ok:
			# save the password locally
			self.password_manager.save_password()

			# create asymmetric credentials
			key = asymmetric_upload_derivation_key(self.zkp.responses, self.zkp.iteration, 32)
			asymmetric_cipher_auth = Cipher_Authentication(key=key)

			# generate asymmetric keys
			self.password_manager.generate_keys()
			response = requests.post(self.save_pk_url, data={
				'client': self.idp_client,
				**self.cipher_auth.create_response(asymmetric_cipher_auth.create_response({
					'key': self.password_manager.get_public_key_str()
				}))
			})

			if response.status_code != 200:
				print(f"Error received from idp: <{response.status_code}: {response.reason}>")
				raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
				                                           params={'error_id': 'zkp_save_keys'}), 301)

			response = asymmetric_cipher_auth.decipher_response(self.cipher_auth.decipher_response(response.json()))
			if 'status' in response and bool(response['status']):
				self.password_manager.save_private_key(user_id=response['user_id'], time_to_live=float(response['ttl']))
		else:
			raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
			                                           params={'error_id': 'zkp_auth_error'}), 301)

		# in the end, we request the attributes with the new key pair
		self.asymmetric_identification()

	@cherrypy.expose
	def keychain(self, username: str, password: str):
		if cherrypy.request.method != 'POST':
			raise cherrypy.HTTPError(405)

		password = password.encode()

		# verify master password
		master_password_manager = Master_Password_Manager(username=username, master_password=password)
		if not master_password_manager.login():
			return Template(filename='static/keychain.html').render(message='Error: Unsuccessful login!')

		self.password_manager = Password_Manager(username=username, master_password=password,
		                                         idp=self.idp)
		if not self.password_manager.load_password():
			return Template(filename='static/authenticate.html').render()
		else:
			if not self.password_manager.load_private_key():
				self.zkp_auth()
			else:
				self.asymmetric_identification()

	@cherrypy.expose
	def attribute_presentation(self):
		response_attrs = json.loads(base64.b64decode(self.response_attrs_b64))
		return Template(filename='static/attr_presentation.html').render(idp=self.idp, sp=self.sp,
		                                                                 response_attrs=response_attrs)

	@cherrypy.expose
	def authorize_attr_response(self, **kwargs):
		if 'deny' in kwargs:
			return Template(filename='static/auth_refused.html').render()
		elif 'allow' in kwargs:
			return Template(filename='static/post_id_attr.html').render(consumer_url=self.consumer_url,
			                                                            response=self.response_attrs_b64,
			                                                            signature=self.response_signature_b64,
			                                                            client=self.sp_client)

	@cherrypy.expose
	def zkp(self, password: str):
		if cherrypy.request.method != 'POST':
			raise cherrypy.HTTPError(405)

		password = password.encode()
		self.password_manager.password = password
		self.zkp_auth()

	@cherrypy.expose
	def authenticate(self, max_iterations, min_iterations, client, key, auth_url, save_pk_url, id_url):
		if cherrypy.request.method != 'GET':
			raise cherrypy.HTTPError(405)

		max_iterations = int(max_iterations)
		min_iterations = int(min_iterations)
		if overlap_intervals(MIN_ITERATIONS_ALLOWED, MAX_ITERATIONS_ALLOWED, min_iterations, max_iterations):
			self.iterations = random.randint(max(MIN_ITERATIONS_ALLOWED, min_iterations),
			                                 min(MAX_ITERATIONS_ALLOWED, max_iterations))
		else:
			raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
			                                           params={'error_id': 'idp_iterations'}), 301)

		self.idp_client = client

		key = base64.urlsafe_b64decode(key)
		self.cipher_auth = Cipher_Authentication(key=key)

		self.auth_url = auth_url
		self.save_pk_url = save_pk_url
		self.id_url = id_url

		return Template(filename='static/keychain.html').render()

	@cherrypy.expose
	def register(self, **kwargs):
		if cherrypy.request.method == 'GET':
			return Template(filename='static/register.html').render()
		elif cherrypy.request.method == 'POST':
			username = kwargs['username']
			master_password = kwargs['password'].encode()

			master_password_manager = Master_Password_Manager(username=username, master_password=master_password)
			if not master_password_manager.register_user():
				return Template(filename='static/register.html').render(
					message='Error: The inserted user already exists!')
			return Template(filename='static/register.html').render(
				message='Success: The user was registered with success')
		else:
			raise cherrypy.HTTPError(405)


if __name__ == '__main__':
	cherrypy.config.update({'server.socket_host': '127.1.2.3',
	                        'server.socket_port': 1080})
	cherrypy.quickstart(HelperApp())
