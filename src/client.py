import socket
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_private_key(path: str):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key


def load_public_key(path: str):
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
    # Assuming private_key is an RSAPrivateKey object, not PEM bytes
    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message.decode()




def receive_message(public_key_pem, sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            data = rsa_decrypt(public_key_pem, data)
            print("Received:", data)
        except Exception as e:
            print(e)
            print("You have been disconnected from the server.")
            break

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 9999

    client_socket.connect((host, port))
    print("Connected to the server. You can start sending messages.")
    
    private_key_pem = load_private_key('client_private_key.pem')
    public_key_pem = load_public_key('client_public_key.pem')
    
    threading.Thread(target=receive_message, args=(private_key_pem, client_socket,)).start()
    
    while True:
        message = input()
        if message == "quit":
            break
        message = rsa_encrypt(public_key_pem, message)
        
        client_socket.sendall(message)

    client_socket.close()

if __name__ == '__main__':
    start_client()