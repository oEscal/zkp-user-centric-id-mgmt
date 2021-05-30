import base64
import json
import uuid
from datetime import datetime, timedelta
from os import urandom

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from utils.utils import create_directory, aes_cipher, asymmetric_padding_signature, asymmetric_hash, \
	aes_key_derivation, asymmetric_padding_encryption


KEYS_DIRECTORY = 'helper_keys'
INITIALIZATION_VECTOR_SIZE = 16
AES_KEY_SALT_SIZE = 16


# noinspection PyBroadException
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
        self.idp_base64 = base64.b64encode(idp.encode()).decode()

        self.password: bytes = b''
        self.user_id: str = ''

        self.salt_private_key: bytes = b''

    def generate_keys(self):
        self.user_id = str(uuid.uuid4())

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def load_password(self) -> bool:
        try:
            with open(f"{KEYS_DIRECTORY}/{self.username}_secret_{self.idp_base64}", "rb") as file:
                salt_password = file.read(AES_KEY_SALT_SIZE)
                self.salt_private_key = file.read(AES_KEY_SALT_SIZE)
                iv = file.read(INITIALIZATION_VECTOR_SIZE)
                ciphered_password = file.read()

            key = aes_key_derivation(self.master_password, salt_password)
            decrypter = aes_cipher(key=key, iv=iv).decryptor()
            block_size = algorithms.AES(key).block_size
            unpadder = padding.PKCS7(block_size).unpadder()
            decrypted_data = decrypter.update(ciphered_password) + decrypter.finalize()
            self.password = unpadder.update(decrypted_data) + unpadder.finalize()

            return True
        except Exception:
            return False

    def load_private_key(self) -> bool:
        try:
            with open(f"{KEYS_DIRECTORY}/{self.username}_{self.idp_base64}.pem", 'rb') as file:
                self.user_id = file.readline().decode().rstrip()
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
        with open(f"{KEYS_DIRECTORY}/{self.username}_secret_{self.idp_base64}", "wb") as file:
            file.write(salt_password)                       # first AES_KEY_SALT_SIZE bytes
            file.write(self.salt_private_key)               # first AES_KEY_SALT_SIZE bytes
            file.write(iv)                                  # first INITIALIZATION_VECTOR_SIZE bytes

            block_size = algorithms.AES(key).block_size
            padder = padding.PKCS7(block_size).padder()
            padded_data = padder.update(self.password) + padder.finalize()
            file.write(encryptor.update(padded_data) + encryptor.finalize())

    def save_private_key(self, time_to_live: float):
        with open(f"{KEYS_DIRECTORY}/{self.username}_{self.idp_base64}.pem", 'wb') as file:
            file.write(f"{self.user_id}\n".encode())
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
