import socket
import threading

def receive_message(sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            print("Received:", data.decode())
        except:
            print("You have been disconnected from the server.")
            break

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 9999

    client_socket.connect((host, port))
    print("Connected to the server. You can start sending messages.")

    threading.Thread(target=receive_message, args=(client_socket,)).start()

    while True:
        message = input()
        if message == "quit":
            break
        client_socket.sendall(message.encode())

    client_socket.close()

if __name__ == '__main__':
    start_client()
