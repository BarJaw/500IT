import db
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from bcrypt import hashpw, gensalt
import hmac
import hashlib



def red_text(text: str) -> str:
    return f"\033[91m{text}\033[0m"


def blue_text(text: str) -> str:
    return f"\033[94m{text}\033[0m"


def green_text(text: str) -> str:
    return f"\033[92m{text}\033[0m"


def hash_password(password):
    return hashpw(password.encode(), gensalt())


def load_private_key(path):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key


def load_public_key(path):
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )
    return public_key


def load_hmac_key(path):
    try:
        with open(path, "rb") as key_file:
            return key_file.read().rstrip()
    except:
        return None

def generate_keys(email):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save the private key
    personal_directory = f'{email}_personal_storage'
    if not os.path.exists(personal_directory):
        os.makedirs(personal_directory)
    with open(f"{personal_directory}/{email}_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save the public key
    public_directory = f'public_keys'
    if not os.path.exists(public_directory):
        os.makedirs(public_directory)
    with open(f"{public_directory}/{email}_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def generate_hmac(secret_key, message):
    # Ensure the key and message are bytes
    secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
    message = message.encode() if isinstance(message, str) else message

    # Create a new HMAC object using SHA-256 as the hash function
    hmac_obj = hmac.new(secret_key, message, hashlib.sha256)
    # Return the HMAC in hexadecimal format
    return hmac_obj.hexdigest()

def verify_hmac(secret_key, message, hmac_to_verify):
    secret_key = secret_key.decode() if isinstance(secret_key, bytes) else secret_key
    message = message.decode() if isinstance(message, bytes) else message

    # Generate HMAC for the incoming message
    generated_hmac = generate_hmac(secret_key, message).encode()
    # Securely compare the generated HMAC with the provided HMAC
    return hmac.compare_digest(generated_hmac, hmac_to_verify)


def rsa_encrypt(public_key, message):
    """
    Encrypts a plain text message using the public RSA key.

    Parameters:
    - public_key: RSAPublicKey object (already loaded from PEM).
    - message: The plain text message as string.

    Returns:
    - The encrypted message as bytes.
    """
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def rsa_decrypt(private_key, encrypted_message):
    """
    Decrypts an encrypted message using the private RSA key.

    Parameters:
    - private_key: RSAPrivateKey object (already loaded from PEM).
    - encrypted_message: The encrypted data as bytes.

    Returns:
    - The decrypted message as a string.
    """
    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message.decode()


def register():
    email = input("Enter your email: ")
    password = input("Enter your password: ")
    password_hash = hash_password(password)
    generate_keys(email)

    if db.register_user(db.conn, email, password_hash):
        print(green_text("Registration successful!"))
    else:
        print(red_text("Registration failed. The email might be already in use."))


def login():
    email = input("Enter your email: ")
    password = input("Enter your password: ")
    if db.authenticate_user(db.conn, email, password):
        print(green_text("Login successful!"))
        return email
    else:
        print(red_text("Login failed. Check your credentials."))



# generate_keys('user1@example.com')
# generate_keys('user2@example.com')
