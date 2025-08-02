import os
import json
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class PrivateValues:
    def __init__(self, path='.privatevalues', password=None, encrypt_keys=False):
        self.path = path
        self.encrypt_keys = encrypt_keys
        self._load_config(password)

    def _derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _load_config(self, password):
        if os.path.exists(self.path):
            with open(self.path, 'r') as f:
                self.config = json.load(f)
            if password is None:
                password = getpass("Enter password: ")
            salt = base64.urlsafe_b64decode(self.config['salt'])
            self.key = self._derive_key(password, salt)
            self.fernet = Fernet(self.key)
            self.encrypt_keys = self.config.get('encrypt_keys', False)

            if 'check' in self.config:
                try:
                    self.fernet.decrypt(self.config['check'].encode())
                except Exception:
                    raise ValueError("Incorrect password or corrupt file.")
            else:
                if self.config['secrets']:
                    try:
                        first_secret_value = list(self.config['secrets'].values())[0]
                        self.fernet.decrypt(first_secret_value.encode())
                    except Exception:
                        raise ValueError("Incorrect password or corrupt file.")
                self.config['check'] = self.fernet.encrypt(b'OK').decode()
                self._save_config()

        else:
            self.config = {
                'salt': base64.urlsafe_b64encode(os.urandom(16)).decode(), 
                'secrets': {},
                'encrypt_keys': self.encrypt_keys
            }
            if password is None:
                password = getpass("Enter new password: ")
            salt = base64.urlsafe_b64decode(self.config['salt'])
            self.key = self._derive_key(password, salt)
            self.fernet = Fernet(self.key)
            self.config['check'] = self.fernet.encrypt(b'OK').decode()
            self._save_config()

    def _save_config(self):
        with open(self.path, 'w') as f:
            json.dump(self.config, f)

    def get(self, key):
        if self.encrypt_keys:
            for encrypted_key, encrypted_value in self.config['secrets'].items():
                try:
                    decrypted_key = self.fernet.decrypt(encrypted_key.encode()).decode()
                    if decrypted_key == key:
                        return self.fernet.decrypt(encrypted_value.encode()).decode()
                except Exception:
                    continue
        else:
            encrypted_value = self.config['secrets'].get(key)
            if encrypted_value:
                return self.fernet.decrypt(encrypted_value.encode()).decode()
        return None

    def set(self, key, value):
        if self.encrypt_keys:
            key_to_update = None
            for encrypted_key in self.config['secrets']:
                try:
                    if self.fernet.decrypt(encrypted_key.encode()).decode() == key:
                        key_to_update = encrypted_key
                        break
                except Exception:
                    continue

            if key_to_update:
                self.config['secrets'][key_to_update] = self.fernet.encrypt(value.encode()).decode()
            else:
                encrypted_key = self.fernet.encrypt(key.encode()).decode()
                self.config['secrets'][encrypted_key] = self.fernet.encrypt(value.encode()).decode()
        else:
            self.config['secrets'][key] = self.fernet.encrypt(value.encode()).decode()
        self._save_config()

    def get_all_keys(self):
        if self.encrypt_keys:
            keys = []
            for encrypted_key in self.config['secrets'].keys():
                try:
                    keys.append(self.fernet.decrypt(encrypted_key.encode()).decode())
                except Exception:
                    continue
            return keys
        else:
            return list(self.config['secrets'].keys())

    def delete(self, key):
        key_to_delete = None
        if self.encrypt_keys:
            for encrypted_key in self.config['secrets']:
                try:
                    if self.fernet.decrypt(encrypted_key.encode()).decode() == key:
                        key_to_delete = encrypted_key
                        break
                except Exception:
                    continue
        else:
            if key in self.config['secrets']:
                key_to_delete = key

        if key_to_delete:
            del self.config['secrets'][key_to_delete]
            self._save_config()
            return True
        return False

    def rename(self, old_key, new_key):
        if self.get(new_key) is not None:
            raise ValueError(f"Key '{new_key}' already exists.")

        key_to_rename = None
        if self.encrypt_keys:
            for encrypted_key in self.config['secrets']:
                try:
                    if self.fernet.decrypt(encrypted_key.encode()).decode() == old_key:
                        key_to_rename = encrypted_key
                        break
                except Exception:
                    continue
        else:
            if old_key in self.config['secrets']:
                key_to_rename = old_key

        if key_to_rename:
            value = self.config['secrets'].pop(key_to_rename)
            if self.encrypt_keys:
                new_encrypted_key = self.fernet.encrypt(new_key.encode()).decode()
                self.config['secrets'][new_encrypted_key] = value
            else:
                self.config['secrets'][new_key] = value
            self._save_config()
            return True
        return False

    def sub_package(self, name, password=None):
        sub_path = f"{self.path}_{name}"
        return PrivateValues(path=sub_path, password=password)