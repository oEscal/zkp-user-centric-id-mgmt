import base64
from datetime import datetime, timedelta
from os import urandom
import random

import requests

import cherrypy
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from mako.template import Template

from utils import ZKP, create_directory, aes_cipher, asymmetric_padding_signature, asymmetric_hash, overlap_intervals, \
    aes_key_derivation, Cipher_Authentication, asymmetric_upload_derivation_variable_based, create_nonce, \
    asymmetric_padding_encryption

"""
DÚVIDAS
 - O IdP tem de obrigar o helper a criar o conjunto de chaves, ou isso é uma opção á escolha da heler?
 - A helper application tem de manter várias chaves para um mesmo utilizador?
 - O segredo para cifrar a chave privada poderá ser a password do utilizador?
 - Quando depois a autenticação é feita com o par de chaves, o utilizador necessita de inserir as credencias de qualquer das formas?
 - O id da public key entre o helper e o idp pode ser por exemplo o id do saml request, já que este é unico?
"""

KEYS_DIRECTORY = 'helper_keys/'
INITIALIZATION_VECTOR_SIZE = 16
AES_KEY_SALT_SIZE = 16

MIN_ITERATIONS_ALLOWED = 10
MAX_ITERATIONS_ALLOWED = 15


class Asymmetric_authentication(object):
    def __init__(self, username: str, password: bytes):
        self.private_key: RSAPrivateKey = None
        self.public_key: RSAPublicKey = None

        self.username = username
        self.password = password

        self.id = self.load_keys()

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def load_keys(self) -> str:
        try:
            with open(f"{KEYS_DIRECTORY}/{self.username}_secret", "rb") as file:
                salt = file.read(AES_KEY_SALT_SIZE)
                iv = file.read(INITIALIZATION_VECTOR_SIZE)
                ciphered_secret = file.read()

            key = aes_key_derivation(self.password, salt)
            decrypter = aes_cipher(key=key, iv=iv).decryptor()
            secret = decrypter.update(ciphered_secret) + decrypter.finalize()

            with open(f"{KEYS_DIRECTORY}/{self.username}.pem", 'rb') as file:
                id = file.readline().decode().rstrip()
                time_to_live = float(file.readline())
                pem = file.read()

            if time_to_live > datetime.now().timestamp():
                self.private_key = load_pem_private_key(
                    data=pem,
                    password=secret,
                    backend=default_backend()
                )
            return id
        except Exception as e:
            print(f"Error: {e}")

    def save_key(self, id: str, time_to_live: float):
        secret = urandom(32)
        create_directory(KEYS_DIRECTORY)

        # save the secret protected by the user password
        iv = urandom(INITIALIZATION_VECTOR_SIZE)
        salt = urandom(AES_KEY_SALT_SIZE)
        key = aes_key_derivation(self.password, salt)
        encryptor = aes_cipher(key=key, iv=iv).encryptor()
        with open(f"{KEYS_DIRECTORY}/{self.username}_secret", "wb") as file:
            file.write(salt)                # first AES_KEY_SALT_SIZE bytes
            file.write(iv)                  # first INITIALIZATION_VECTOR_SIZE bytes
            file.write(encryptor.update(secret) + encryptor.finalize())

        # save the private key protected with the secret
        with open(f"{KEYS_DIRECTORY}/{self.username}.pem", 'wb') as file:
            file.write(f"{id}\n".encode())
            file.write(f"{(datetime.now() + timedelta(minutes=time_to_live)).timestamp()}\n".encode())
            file.write(self.get_private_key_bytes(secret))

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data=data, padding=asymmetric_padding_signature(), algorithm=asymmetric_hash())

    def decrypt(self, data: bytes) -> bytes:
        return self.private_key.decrypt(data, padding=asymmetric_padding_encryption())

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
        self.cipher_auth: Cipher_Authentication = None

    @staticmethod
    def static_contents(path):
        return open(f"static/{path}", 'r').read()

    @cherrypy.expose
    def index(self):
        raise cherrypy.HTTPRedirect('/authenticate')

    def asymmetric_auth(self, asymmetric_authentication: Asymmetric_authentication, username: str,
                        password: bytes, saml_id: str):
        nonce_to_send = create_nonce()
        ciphered_params = self.cipher_auth.cipher_data({
            'id': asymmetric_authentication.id,
            'nonce': nonce_to_send.decode(),
            'username': username
        })
        response = requests.get(f"http://localhost:8082/authenticate_asymmetric",
                                params={
                                    'saml_id': saml_id,
                                    'ciphered': ciphered_params
                                })
        if response.status_code != 200:
            print(f"Error status: {response.status_code}")
            self.zkp_auth(asymmetric_authentication, username=username, password=password, saml_id=saml_id)
        else:
            response_dict = self.cipher_auth.decipher_data(response.text)

            # verify the authenticity of the IdP
            if ('response' not in response_dict
                    or nonce_to_send != asymmetric_authentication.decrypt(base64.urlsafe_b64decode(response_dict['response']))):
                return Template(filename='static/error.html').render(
                    message='The response to the challenge sent to the IdP to authentication '
                            'with asymmetric keys is not valid. A possible cause for this is '
                            'the IdP we are contacting is not a trusted one!')
            else:
                nonce = response_dict['nonce'].encode()
                challenge_response = asymmetric_authentication.sign(nonce)
                response = requests.get(f"http://localhost:8082/authenticate_asymmetric",
                                        params={
                                            'saml_id': saml_id,
                                            'ciphered': self.cipher_auth.cipher_data({
                                                'response': base64.urlsafe_b64encode(challenge_response).decode()
                                            })
                                        })
                if response.status_code != 200:
                    print(f"Error status: {response.status_code}")
                    self.zkp_auth(asymmetric_authentication, username=username, password=password, saml_id=saml_id)

    def zkp_auth(self, asymmetric_authentication: Asymmetric_authentication, username: str,
                 password: bytes, saml_id: str):
        zkp = ZKP(password)
        data_send = {
            'nonce': '',
        }
        for i in range(self.iterations):
            data_send['nonce'] = zkp.create_challenge()
            ciphered_params = self.cipher_auth.cipher_data({**data_send,
                        **({'username': username, 'iterations': self.iterations} if zkp.iteration < 2 else {})})
            response = requests.get(f"http://localhost:8082/authenticate", params={
                'ciphered': ciphered_params,
                'id': saml_id
            })

            if response.status_code == 200:
                # verify if response to challenge is correct
                response_dict = self.cipher_auth.decipher_data(response.text)
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
        iv = asymmetric_upload_derivation_variable_based(zkp.responses, len(zkp.password), 16)
        asymmetric_cipher_auth = Cipher_Authentication(key=key, iv=iv)

        # generate asymmetric keys
        asymmetric_authentication.generate_keys()
        response = requests.post("http://localhost:8082/save_asymmetric", data={
            'id': saml_id,
            'ciphered': self.cipher_auth.cipher_data(asymmetric_cipher_auth.cipher_data({
                'key': asymmetric_authentication.get_public_key_str()
            }))
        })

        response = asymmetric_cipher_auth.decipher_data(self.cipher_auth.decipher_data(response.text))
        if 'status' in response and bool(response['status']):
            asymmetric_authentication.save_key(id=saml_id, time_to_live=float(response['ttl']))

    @cherrypy.expose
    def authenticate(self, **kwargs):
        if cherrypy.request.method == 'GET':
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
            
            key = base64.urlsafe_b64decode(kwargs['key'])
            iv = base64.urlsafe_b64decode(kwargs['iv'])
            self.cipher_auth = Cipher_Authentication(key=key, iv=iv)
            
            return Template(filename='static/authenticate.html').render(id=kwargs['id'])
        elif cherrypy.request.method == 'POST':
            username = kwargs['username']
            password = kwargs['password'].encode()

            asymmetric_authentication = Asymmetric_authentication(username=username, password=password)
            if asymmetric_authentication.private_key:
                self.asymmetric_auth(asymmetric_authentication, username=username, password=password,
                                     saml_id=kwargs['id'])
            else:
                template = self.zkp_auth(asymmetric_authentication,
                                         username=username, password=password, saml_id=kwargs['id'])
                if template:
                    return template
            raise cherrypy.HTTPRedirect(f"http://localhost:8082/identity?id={kwargs['id']}")


if __name__ == '__main__':
    cherrypy.config.update({'server.socket_host': '127.1.2.3',
                            'server.socket_port': 1080})
    cherrypy.quickstart(HelperApp())
