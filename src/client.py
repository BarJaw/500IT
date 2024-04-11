from utils import *
import socket
import threading



def receive_message(hmac_key, private_key_pem, sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            message, hmac = data[:-64], data[-64:]
            message = rsa_decrypt(private_key_pem, message)
            if hmac_key is not None:
                is_hmac_correct = verify_hmac(hmac_key, message, hmac)
            else:
                is_hmac_correct = False
            if is_hmac_correct:
                print("Received:", message)
            else:
                print(red_text('Hmac is incorrect or missing key! The integrity is in danger.'))
        except Exception as e:
            print(e)
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
        hmac_key = load_hmac_key(f'{email}_personal_storage/super_secret_hmac_key.hmac')
    except Exception as e:
        print(red_text('Your encryption setup is missing. Please ensure the keys are in the correct locations.'))
        exit()
    threading.Thread(target=receive_message, args=(hmac_key, private_key_pem, client_socket,)).start()
    
    while True:
        message = input()
        if message == 'quit':
            break
        hmac = generate_hmac(hmac_key, message).encode()
        message = rsa_encrypt(public_key_pem, message)
        data_to_send = message + hmac
        client_socket.sendall(data_to_send)
    client_socket.close()

def main():
    while True:
        print(blue_text("Welcome! Please choose an option:"))
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