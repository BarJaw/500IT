import db
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from bcrypt import hashpw, gensalt


def red_text(text: str) -> str:
    return f"\033[91m{text}\033[0m"


def blue_text(text: str) -> str:
    return f"\033[94m{text}\033[0m"


def green_text(text: str) -> str:
    return f"\033[92m{text}\033[0m"


def hash_password(password):
    return hashpw(password.encode(), gensalt())


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

def register():
    email = input("Enter your email: ")
    password = input("Enter your password: ")
    password_hash = hash_password(password)
    generate_keys(email)

    if db.register_user(db.conn, email, password_hash):
        print("Registration successful!")
    else:
        print("Registration failed. The email might be already in use.")


def login():
    email = input("Enter your email: ")
    password = input("Enter your password: ")
    password_hash = hash_password(password)

    if db.authenticate_user(db.conn, email, password_hash):
        print(green_text("Login successful!"))
    else:
        print(red_text("Login failed. Check your credentials."))

    return email
# generate_keys('user1@example.com')
# generate_keys('user2@example.com')
