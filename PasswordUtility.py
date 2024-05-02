import base64

from import_file import *


class PasswordUtility:
    def encrypt_password(self, password, encryption_key=None):
        if encryption_key is None:
            encryption_key = self.__generate_encryption_key__(password)

        encryption_result = self.__encrypt_data__(password, encryption_key)
        return encryption_result

    def decrypt_password(self, encrypted_password, encryption_key):
        return self.__decrypt_data__(encrypted_password, encryption_key)

    @staticmethod
    def __encrypt_data__(data, encryption_key):
        # Convert data to bytes
        data_bytes = data.encode('utf-8')

        # Generate a random initialization vector (IV) for encryption
        iv = os.urandom(16)

        # Pad the data to be a multiple of 16 bytes (AES block size)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data_bytes) + padder.finalize()

        # Encrypt the data using AES-256-CBC with the provided encryption key
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Combine IV and ciphertext and encode in base64 for storage
        encrypted_data = urlsafe_b64encode(iv + ciphertext).decode('utf-8')
        encryption_key = base64.b64encode(encryption_key).decode()

        return {'encrypted_data': encrypted_data, 'encryption_key': encryption_key}

    @staticmethod
    def __decrypt_data__(encrypted_data, encryption_key):
        # Decode base64-encoded encrypted data
        encrypted_data_bytes = urlsafe_b64decode(encrypted_data.encode('utf-8'))

        # Extract IV and ciphertext
        iv = encrypted_data_bytes[:16]
        ciphertext = encrypted_data_bytes[16:]

        # Decrypt the ciphertext using AES-256-CBC with the provided encryption key and IV
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data_bytes = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the decrypted data to get the original data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_data_bytes) + unpadder.finalize()

        return decrypted_data.decode('utf-8')

    @staticmethod
    def __generate_encryption_key__(password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key for AES-256
            salt=b'salt',  # You should use a unique salt per master password
            iterations=100000,
            backend=default_backend()
        )
        encryption_key = kdf.derive(password.encode('utf-8'))
        return encryption_key
