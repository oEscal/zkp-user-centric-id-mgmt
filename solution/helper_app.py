from os import urandom

import requests

import cherrypy
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from mako.template import Template

from utils import ZKP, create_directory, aes_key_derivation, aes_cipher

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


class Asymmetric_authentication(object):
    def __init__(self, username: str, password: bytes):
        self.private_key: RSAPrivateKey = None
        self.public_key: RSAPublicKey = None

        self.username = username
        self.password = password

        self.load_keys()

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def load_keys(self):
        try:
            with open(f"{KEYS_DIRECTORY}/{self.username}_secret", "rb") as file:
                salt = file.read(AES_KEY_SALT_SIZE)
                iv = file.read(INITIALIZATION_VECTOR_SIZE)
                ciphered_secret = file.read()

            decrypter = aes_cipher(password=self.password, iv=iv, salt=salt).decryptor()
            secret = decrypter.update(ciphered_secret) + decrypter.finalize()

            with open(f"{KEYS_DIRECTORY}/{self.username}.pem", 'rb') as file:
                id = file.readline()
                time_to_live = file.readline()
                pem = file.read()

            if time_to_live:
                self.private_key = load_pem_private_key(
                    data=pem,
                    password=secret,
                    backend=default_backend()
                )
            print(self.private_key)
        except Exception as e:
            print(f"Error: {e}")

    def save_key(self, id: str, time_to_live: int):
        secret = urandom(32)
        create_directory(KEYS_DIRECTORY)

        # save the secret protected by the user password
        iv = urandom(INITIALIZATION_VECTOR_SIZE)
        salt = urandom(AES_KEY_SALT_SIZE)
        encryptor = aes_cipher(password=self.password, iv=iv, salt=salt).encryptor()
        with open(f"{KEYS_DIRECTORY}/{self.username}_secret", "wb") as file:
            file.write(salt)                # first AES_KEY_SALT_SIZE bytes
            file.write(iv)                  # first INITIALIZATION_VECTOR_SIZE bytes
            file.write(encryptor.update(secret) + encryptor.finalize())

        # save the private key protected with the secret
        with open(f"{KEYS_DIRECTORY}/{self.username}.pem", 'wb') as file:
            file.write(f"{id}\n".encode())
            file.write(f"{time_to_live}\n".encode())
            file.write(self.get_private_key_bytes(secret))

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
            username = kwargs['username']
            password = kwargs['password'].encode()

            asymmetric_authentication = Asymmetric_authentication(username=username, password=password)
            if asymmetric_authentication.private_key:
                pass
            else:
                zkp = ZKP(password)
                data_send = {
                    'nonce': '',
                    'id': kwargs['id']
                }
                for i in range(self.iterations):
                    data_send['nonce'] = zkp.create_challenge()
                    response = requests.get(f"http://localhost:8082/authenticate",
                                            params={**data_send,
                                                    **({'username': username} if zkp.iteration < 2 else {})})

                    # verify if response to challenge is correct
                    idp_response = response.json()['response']
                    zkp.verify_challenge_response(idp_response)

                    # create both response to the IdP challenge and new challenge to the IdP
                    challenge: bytes = response.json()['nonce'].encode()
                    challenge_response = zkp.response(challenge)
                    data_send['response'] = challenge_response

                # generate asymmetric keys
                asymmetric_authentication.generate_keys()
                response = requests.post("http://localhost:8082/save_asymmetric", data={
                    'id': kwargs['id'],
                    'key': asymmetric_authentication.get_public_key_str()
                })

                response = response.json()
                if 'status' in response and response['status']:
                    asymmetric_authentication.save_key(id=kwargs['id'], time_to_live=123)

                # after the ZKP
                raise cherrypy.HTTPRedirect(f"http://localhost:8082/identity?id={kwargs['id']}")


if __name__ == '__main__':
    cherrypy.config.update({'server.socket_host': '127.1.2.3',
                            'server.socket_port': 1080})
    cherrypy.quickstart(HelperApp())
