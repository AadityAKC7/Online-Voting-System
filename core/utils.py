

import base64
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature, InvalidKey

def decrypt_rsa(encrypted_base64_str):
    try:
        with open(r'C:\Users\H P\OneDrive\Desktop\Project 2\private_key.pem', 'rb') as key_file:
            private_key = load_pem_private_key(key_file.read(), password=None)

        encrypted_bytes = base64.b64decode(encrypted_base64_str)
        decrypted_bytes = private_key.decrypt(encrypted_bytes, padding.PKCS1v15())
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        # Log or print detailed error
        print(f"Decryption failed: {e}")
        raise