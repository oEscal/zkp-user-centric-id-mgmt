import base64
import json
from datetime import datetime, timedelta
from os import urandom
import random

import requests

import cherrypy
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from mako.template import Template

from utils import ZKP, create_directory, aes_cipher, asymmetric_padding_signature, asymmetric_hash, overlap_intervals, \
    aes_key_derivation, Cipher_Authentication, asymmetric_upload_derivation_variable_based, create_nonce, \
    asymmetric_padding_encryption, create_get_url

"""
DÚVIDAS
 - O IdP tem de obrigar o helper a criar o conjunto de chaves, ou isso é uma opção á escolha da heler?
 - A helper application tem de manter várias chaves para um mesmo utilizador?
 - O segredo para cifrar a chave privada poderá ser a password do utilizador?
 - Quando depois a autenticação é feita com o par de chaves, o utilizador necessita de inserir as credencias de qualquer das formas?
 - O id da public key entre o helper e o idp pode ser por exemplo o id do saml request, já que este é unico?
"""

KEYS_DIRECTORY = 'helper_keys'
INITIALIZATION_VECTOR_SIZE = 16
AES_KEY_SALT_SIZE = 16
USER_ID_SIZE = 16

MIN_ITERATIONS_ALLOWED = 10
MAX_ITERATIONS_ALLOWED = 15


class Master_Password_Manager(object):
    def __init__(self, username: str, master_password: bytes):
        self.username = username
        self.master_password = master_password

        self.create_file_if_not_exist()

    def register_user(self) -> bool:
        with open(f"{KEYS_DIRECTORY}/users.json", "r+") as file:
            users = {}
            try:
                users = json.load(file)
            except Exception:
                pass

            if self.username in users:
                return False

            salt = urandom(AES_KEY_SALT_SIZE)
            users[self.username] = {}
            users[self.username]['salt'] = base64.b64encode(salt).decode()
            users[self.username]['password'] = base64.b64encode(
                self.derivation_function(salt).derive(self.master_password)
            ).decode()
            file.seek(0, 0)
            json.dump(users, file)

        return True

    def login(self) -> bool:
        with open(f"{KEYS_DIRECTORY}/users.json", "r") as file:
            users = json.load(file)

        if self.username not in users:
            return False

        salt = base64.b64decode(users[self.username]['salt'])
        key = base64.b64decode(users[self.username]['password'])
        try:
            self.derivation_function(salt).verify(self.master_password, key)
        except InvalidKey:
            return False

        return True

    @staticmethod
    def derivation_function(salt) -> Scrypt:
        return Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1
        )

    @staticmethod
    def create_file_if_not_exist():
        # create file if not exist
        with open(f"{KEYS_DIRECTORY}/users.json", "a+"):
            pass


# noinspection PyBroadException,PyTypeChecker
class Password_Manager(object):
    def __init__(self, username: str, master_password: bytes, idp: str):
        self.private_key: RSAPrivateKey = None
        self.public_key: RSAPublicKey = None

        self.username = username
        self.master_password = master_password
        self.idp = idp

        self.password: bytes = b''
        self.user_id: bytes = b''

        self.salt_private_key: bytes = b''

    def generate_keys(self):
        self.user_id = urandom(USER_ID_SIZE)

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def load_password(self) -> bool:
        try:
            with open(f"{KEYS_DIRECTORY}/{self.username}_secret_{base64.b64encode(self.idp.encode())}", "rb") as file:
                salt_password = file.read(AES_KEY_SALT_SIZE)
                self.salt_private_key = file.read(AES_KEY_SALT_SIZE)
                iv = file.read(INITIALIZATION_VECTOR_SIZE)
                ciphered_password = file.read()

            key = aes_key_derivation(self.master_password, salt_password)
            decrypter = aes_cipher(key=key, iv=iv).decryptor()
            self.password = decrypter.update(ciphered_password) + decrypter.finalize()

            return True
        except Exception:
            return False

    def load_private_key(self) -> bool:
        try:
            with open(f"{KEYS_DIRECTORY}/{self.username}_{base64.b64encode(self.idp.encode())}.pem", 'rb') as file:
                self.user_id = file.read(USER_ID_SIZE)
                time_to_live = float(file.readline())
                pem = file.read()

            if time_to_live > datetime.now().timestamp():
                self.private_key = load_pem_private_key(
                    data=pem,
                    password=self.private_key_secret(),
                    backend=default_backend()
                )
            else:
                return False

            return True
        except Exception:
            return False

    def save_password(self, password: bytes):
        self.password = password

        create_directory(KEYS_DIRECTORY)

        iv = urandom(INITIALIZATION_VECTOR_SIZE)
        salt_password = urandom(AES_KEY_SALT_SIZE)
        self.salt_private_key = urandom(AES_KEY_SALT_SIZE)
        key = aes_key_derivation(self.master_password, salt_password)
        encryptor = aes_cipher(key=key, iv=iv).encryptor()
        with open(f"{KEYS_DIRECTORY}/{self.username}_secret_{base64.b64encode(self.idp.encode())}", "wb") as file:
            file.write(salt_password)                       # first AES_KEY_SALT_SIZE bytes
            file.write(self.salt_private_key)               # first AES_KEY_SALT_SIZE bytes
            file.write(iv)                                  # first INITIALIZATION_VECTOR_SIZE bytes
            file.write(encryptor.update(self.password) + encryptor.finalize())

    def save_private_key(self, time_to_live: float):
        with open(f"{KEYS_DIRECTORY}/{self.username}_{base64.b64encode(self.idp.encode())}.pem", 'wb') as file:
            file.write(self.user_id)
            file.write(f"{(datetime.now() + timedelta(minutes=time_to_live)).timestamp()}\n".encode())
            file.write(self.get_private_key_bytes(secret=self.private_key_secret()))

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data=data, padding=asymmetric_padding_signature(), algorithm=asymmetric_hash())

    def decrypt(self, data: bytes) -> bytes:
        return self.private_key.decrypt(data, padding=asymmetric_padding_encryption())

    def private_key_secret(self) -> bytes:
        return aes_key_derivation(self.master_password + self.password, salt=self.salt_private_key)

    def get_private_key_bytes(self, secret: bytes) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password=secret)
        )

    def get_public_key_str(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()


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

    def asymmetric_auth(self):
        nonce_to_send = create_nonce()
        ciphered_params = self.cipher_auth.create_response({
            'id': self.password_manager.user_id,
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
                return Template(filename='static/error.html').render(
                    message='The response to the challenge sent to the IdP to authentication '
                            'with asymmetric keys is not valid. A possible cause for this is '
                            'the IdP we are contacting is not a trusted one!')
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
                return Template(filename='static/error.html').render(
                    message=f"Received the status code <{response.status_code}: {response.reason}> from the IdP")

        key = asymmetric_upload_derivation_variable_based(zkp.responses, zkp.iteration, 32)
        asymmetric_cipher_auth = Cipher_Authentication(key=key)

        # generate asymmetric keys
        self.password_manager.generate_keys()
        response = requests.post(f"{self.idp}/save_asymmetric", data={
            'id': self.password_manager.user_id,
            **self.cipher_auth.create_response(asymmetric_cipher_auth.create_response({
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
    def zkp(self, password: str):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)

        password = password.encode()
        self.password_manager.save_password(password=password)
        self.zkp_auth()

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
            return Template(filename='static/error.html').render(
                message='The range of allowed iterations received from the IdP is incompatible with the range '
                        'allowed by the local app. A possible cause for this is the IdP we are contacting is not '
                        'a trusted one!')

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
