import base64
import random

import cherrypy
import requests
from mako.template import Template

import sys
sys.path.append('..')

from managers import Master_Password_Manager, Password_Manager
from utils.utils import ZKP, overlap_intervals, \
    Cipher_Authentication, asymmetric_upload_derivation_variable_based, create_nonce, \
    create_get_url

MIN_ITERATIONS_ALLOWED = 10
MAX_ITERATIONS_ALLOWED = 15


class HelperApp(object):
    def __init__(self):
        self.iterations = 0
        self.idp = None
        self.saml_id: str = ''
        self.cipher_auth: Cipher_Authentication = None
        self.password_manager: Password_Manager = None

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
                              "a trusted one!"

        }
        return Template(filename='static/error.html').render(message=errors[error_id])

    def asymmetric_auth(self):
        nonce_to_send = create_nonce()
        ciphered_params = self.cipher_auth.create_response({
            'user_id': self.password_manager.user_id,
            'nonce': nonce_to_send.decode(),
            'username': self.password_manager.username
        })
        response = requests.get(f"{self.idp}/authenticate_asymmetric",
                                params={
                                    'saml_id': self.saml_id,
                                    **ciphered_params
                                })
        if response.status_code != 200:
            print(f"Error status: {response.status_code}")
            self.zkp_auth()
        else:
            response_dict = self.cipher_auth.decipher_response(response.json())

            # verify the authenticity of the IdP
            if ('response' not in response_dict
                    or nonce_to_send != self.password_manager.decrypt(base64.urlsafe_b64decode(response_dict['response']))):
                raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                           params={'error_id': 'asymmetric_challenge'}), 301)
            else:
                nonce = response_dict['nonce'].encode()
                challenge_response = self.password_manager.sign(nonce)
                response = requests.get(f"{self.idp}/authenticate_asymmetric",
                                        params={
                                            'saml_id': self.saml_id,
                                            **self.cipher_auth.create_response({
                                                'response': base64.urlsafe_b64encode(challenge_response).decode()
                                            })
                                        })
                if response.status_code != 200:
                    print(f"Error status: {response.status_code}")
                    self.zkp_auth()

    def zkp_auth(self):
        zkp = ZKP(self.password_manager.password)
        data_send = {
            'nonce': '',
        }
        for i in range(self.iterations):
            data_send['nonce'] = zkp.create_challenge()
            ciphered_params = self.cipher_auth.create_response({
                **data_send,
                **({
                       'username': self.password_manager.username,
                       'iterations': self.iterations
                   } if zkp.iteration < 2 else {})
            })
            response = requests.get(f"{self.idp}/authenticate", params={
                'id': self.saml_id,
                **ciphered_params
            })

            if response.status_code == 200:
                # verify if response to challenge is correct
                response_dict = self.cipher_auth.decipher_response(response.json())
                idp_response = int(response_dict['response'])
                zkp.verify_challenge_response(idp_response)

                # create both response to the IdP challenge and new challenge to the IdP
                challenge = response_dict['nonce'].encode()
                challenge_response = zkp.response(challenge)
                data_send['response'] = challenge_response
            else:
                print(f"Error received from idp: <{response.status_code}: {response.reason}>")
                raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                           params={'error_id': 'zkp_idp_error'}), 301)

        key = asymmetric_upload_derivation_variable_based(zkp.responses, zkp.iteration, 32)
        asymmetric_cipher_auth = Cipher_Authentication(key=key)

        # generate asymmetric keys
        self.password_manager.generate_keys()
        response = requests.post(f"{self.idp}/save_asymmetric", data={
            'saml_id': self.saml_id,
            **self.cipher_auth.create_response(asymmetric_cipher_auth.create_response({
                'user_id': self.password_manager.user_id,
                'key': self.password_manager.get_public_key_str()
            }))
        })

        response = asymmetric_cipher_auth.decipher_response(self.cipher_auth.decipher_response(response.json()))
        if 'status' in response and bool(response['status']):
            self.password_manager.save_private_key(time_to_live=float(response['ttl']))

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
            return Template(filename='static/authenticate.html').render(id=self.saml_id)
        else:
            if not self.password_manager.load_private_key():
                self.zkp_auth()
            else:
                self.asymmetric_auth()

        raise cherrypy.HTTPRedirect(create_get_url(f"{self.idp}/identity",
                                                   params={'id': self.saml_id}))

    @cherrypy.expose
    def zkp(self, password: str, id: str):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)

        password = password.encode()
        self.password_manager.save_password(password=password)
        self.zkp_auth()

        raise cherrypy.HTTPRedirect(create_get_url(f"{self.idp}/identity",
                                                   params={'id': self.saml_id}))

    @cherrypy.expose
    def authenticate(self, **kwargs):
        if cherrypy.request.method != 'GET':
            raise cherrypy.HTTPError(405)

        self.idp = base64.urlsafe_b64decode(kwargs['idp']).decode()

        max_iterations = int(kwargs['max_iterations'])
        min_iterations = int(kwargs['min_iterations'])
        if overlap_intervals(MIN_ITERATIONS_ALLOWED, MAX_ITERATIONS_ALLOWED, min_iterations, max_iterations):
            self.iterations = random.randint(max(MIN_ITERATIONS_ALLOWED, min_iterations),
                                             min(MAX_ITERATIONS_ALLOWED, max_iterations))
        else:
            raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                       params={'error_id': 'idp_iterations'}), 301)

        self.saml_id = kwargs['id']

        key = base64.urlsafe_b64decode(kwargs['key'])
        self.cipher_auth = Cipher_Authentication(key=key)

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