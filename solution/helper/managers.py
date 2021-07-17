import base64
import json
from datetime import datetime, timedelta
from os import urandom, rename, path

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
        self.idps = {}

        self.create_file_if_not_exist()

    def register_user(self) -> bool:
        with open(f"{KEYS_DIRECTORY}/users.json", "r+") as file:
            try:
                users = json.load(file)
            except Exception:
                return False

            if self.username in users:
                return False

            salt = urandom(AES_KEY_SALT_SIZE)
            users[self.username] = {}
            users[self.username]['salt'] = base64.b64encode(salt).decode()
            users[self.username]['password'] = base64.b64encode(
                self.derivation_function(salt).derive(self.master_password)
            ).decode()

            users[self.username]['idps'] = {}

            file.seek(0, 0)
            json.dump(users, file)
            file.truncate()

        return True

    def update_user(self, new_username: str = '', new_password: str = '') -> bool:
        with open(f"{KEYS_DIRECTORY}/users.json", "r+") as file:
            try:
                users = json.load(file)
            except Exception:
                return False

            # update the username
            if new_username:
                if new_username in users:
                    return False
                users[new_username] = users.pop(self.username)
                self.username = new_username

            # update the password
            if new_password:
                salt = urandom(AES_KEY_SALT_SIZE)
                users[self.username]['salt'] = base64.b64encode(salt).decode()
                users[self.username]['password'] = base64.b64encode(
                    self.derivation_function(salt).derive(new_password)
                ).decode()

                self.master_password = new_password

            file.seek(0, 0)
            json.dump(users, file)
            file.truncate()

            return True

    def add_idp_user(self, idp_user: str, idp: str) -> bool:
        with open(f"{KEYS_DIRECTORY}/users.json", "r+") as file:
            try:
                users = json.load(file)
            except Exception:
                return False

            if idp not in users[self.username]['idps']:
                users[self.username]['idps'][idp] = []

            if idp_user in users[self.username]['idps'][idp]:
                return False

            users[self.username]['idps'][idp].append(idp_user)
            self.idps = users[self.username]['idps']

            file.seek(0, 0)
            json.dump(users, file)
            file.truncate()

        return True

    def update_idp_user(self, previous_idp_user: str, idp: str, new_idp_user: str) -> bool:
        with open(f"{KEYS_DIRECTORY}/users.json", "r+") as file:
            try:
                users = json.load(file)
            except Exception:
                return False

            if (idp not in self.idps or previous_idp_user not in users[self.username]['idps'][idp]
                    or new_idp_user in users[self.username]['idps'][idp]):
                return False

            del users[self.username]['idps'][idp][users[self.username]['idps'][idp].index(previous_idp_user)]
            users[self.username]['idps'][idp].append(new_idp_user)

            self.idps = users[self.username]['idps']

            file.seek(0, 0)
            json.dump(users, file)
            file.truncate()

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

        self.idps = users[self.username]['idps']

        return True

    def get_users_for_idp(self, idp: str) -> list:
        if idp not in self.idps:
            return []
        return self.idps[idp]

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
    def __init__(self, master_username: str, master_password: bytes, idp_user: str, idp: str):
        self.private_key: RSAPrivateKey = None
        self.public_key: RSAPublicKey = None

        self.master_username = master_username
        self.master_password = master_password

        self.idp_username = idp_user
        self.idp = idp
        self.idp_base64 = base64.b64encode(idp.encode()).decode()

        self.password: bytes = b''
        self.user_id: str = ''
        self.time_to_live: str = ''

        self.salt_private_key: bytes = b''

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def load_password(self) -> bool:
        try:
            with open(f"{KEYS_DIRECTORY}/{self.idp_username}_secret_{self.master_username}_{self.idp_base64}", "rb") \
                    as file:
                salt_password = file.read(AES_KEY_SALT_SIZE)
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

    def load_private_key(self, no_time_verification=False) -> bool:
        try:
            with open(f"{KEYS_DIRECTORY}/{self.idp_username}_{self.master_username}_{self.idp_base64}.pem", 'rb') as file:
                self.user_id = file.readline().decode().rstrip()
                self.time_to_live = float(file.readline())
                self.salt_private_key = file.read(AES_KEY_SALT_SIZE)
                pem = file.read()

            if not no_time_verification and not self.time_to_live > datetime.now().timestamp():
                return False

            self.private_key = load_pem_private_key(
                data=pem,
                password=self.private_key_secret(),
                backend=default_backend()
            )

            return True
        except Exception as e:
            print(f"Error in function {self.load_private_key.__name__}: {e}")
            return False

    def save_password(self):
        create_directory(KEYS_DIRECTORY)

        iv = urandom(INITIALIZATION_VECTOR_SIZE)
        salt_password = urandom(AES_KEY_SALT_SIZE)
        key = aes_key_derivation(self.master_password, salt_password)
        encryptor = aes_cipher(key=key, iv=iv).encryptor()
        with open(f"{KEYS_DIRECTORY}/{self.idp_username}_secret_{self.master_username}_{self.idp_base64}", "wb") as file:
            file.write(salt_password)                       # first AES_KEY_SALT_SIZE bytes
            file.write(iv)                                  # first INITIALIZATION_VECTOR_SIZE bytes

            block_size = algorithms.AES(key).block_size
            padder = padding.PKCS7(block_size).padder()
            padded_data = padder.update(self.password) + padder.finalize()
            file.write(encryptor.update(padded_data) + encryptor.finalize())

    def save_private_key(self, user_id: str, time_to_live: float):
        self.user_id = user_id

        self.salt_private_key = urandom(AES_KEY_SALT_SIZE)
        with open(f"{KEYS_DIRECTORY}/{self.idp_username}_{self.master_username}_{self.idp_base64}.pem", 'wb') as file:
            file.write(f"{self.user_id}\n".encode())
            file.write(f"{(datetime.now() + timedelta(minutes=time_to_live)).timestamp()}\n".encode())
            file.write(self.salt_private_key)  # first AES_KEY_SALT_SIZE bytes
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

    @staticmethod
    def update_keychain_user(prev_username: str, new_username: str, idps: list):
        for idp in idps:
            for idp_username in idps[idp]:
                idp_base64 = base64.b64encode(idp.encode()).decode()

                # change the password file name
                password_path = f"{KEYS_DIRECTORY}/{idp_username}_secret_{prev_username}_{idp_base64}"
                if path.exists(password_path):
                    rename(password_path, f"{KEYS_DIRECTORY}/{idp_username}_secret_{new_username}_{idp_base64}")

                # change the private key file name if exists
                private_key_path = f"{KEYS_DIRECTORY}/{idp_username}_{prev_username}_{idp_base64}.pem"
                if path.exists(private_key_path):
                    print("adeus")
                    rename(private_key_path, f"{KEYS_DIRECTORY}/{idp_username}_{new_username}_{idp_base64}.pem")

    @staticmethod
    def update_idp_username(master_username: str, previous_idp_user: str, new_idp_user: str, idp: str):
        idp_base64 = base64.b64encode(idp.encode()).decode()

        # change the password file name
        password_path = f"{KEYS_DIRECTORY}/{previous_idp_user}_secret_{master_username}_{idp_base64}"
        if path.exists(password_path):
            rename(password_path, f"{KEYS_DIRECTORY}/{new_idp_user}_secret_{master_username}_{idp_base64}")

        # change the private key file name if exists
        private_key_path = f"{KEYS_DIRECTORY}/{previous_idp_user}_{master_username}_{idp_base64}.pem"
        if path.exists(private_key_path):
            rename(private_key_path, f"{KEYS_DIRECTORY}/{new_idp_user}_{master_username}_{idp_base64}.pem")

    def update_idp_password(self, new_password: bytes) -> bool:
        password_path = f"{KEYS_DIRECTORY}/{self.idp_username}_secret_{self.master_username}_{self.idp_base64}"
        if not self.load_password() and path.exists(password_path):
            return False

        private_key_load_success = self.load_private_key(no_time_verification=True)

        self.password = new_password
        self.save_password()

        if private_key_load_success:
            self.salt_private_key = urandom(AES_KEY_SALT_SIZE)
            with open(f"{KEYS_DIRECTORY}/{self.idp_username}_{self.master_username}_{self.idp_base64}.pem", 'wb') as file:
                file.write(f"{self.user_id}\n".encode())
                file.write(f"{self.time_to_live}\n".encode())
                file.write(self.salt_private_key)  # first AES_KEY_SALT_SIZE bytes
                file.write(self.get_private_key_bytes(secret=self.private_key_secret()))

        return True
