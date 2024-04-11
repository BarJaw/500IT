from utils import *
from server import start_server
import socket
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


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


def receive_message(private_key_pem, sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            data = rsa_decrypt(private_key_pem, data)
            print("Received:", data)
        except Exception as e:
            print(blue_text("You have been disconnected from the server."))
            break
    
def start_client(email):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 9999
    client_socket.connect((host, port))
    other_email = input(blue_text(f'Connected to the server as {email}. What is the email of the person you want to contact? '))
    try:
        private_key_pem = load_private_key(f'{email}_personal_storage/{email}_private_key.pem')
        public_key_pem = load_public_key(f'public_keys/{other_email}_public_key.pem')
    except Exception as e:
        print(red_text('Your encryption setup is missing. Please ensure the keys are in the correct locations.'))
        exit()
    threading.Thread(target=receive_message, args=(private_key_pem, client_socket,)).start()
    
    while True:
        message = input()
        if message == 'quit':
            break
        message = rsa_encrypt(public_key_pem, message)
        
        client_socket.sendall(message)
    client_socket.close()

def main():
    while True:
        print("Welcome! Please choose an option:")
        print("1. Login to the chat")
        print("2. Register")
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == '1':
            email = login()
            if email:
                start_client(email)
        elif choice == '2':
            register()
        elif choice == '3':
            print(blue_text("Exiting program."))
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == '__main__':
    main()