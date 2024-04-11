import socket
import threading
from utils import green_text, blue_text, red_text

def client_thread(conn, other_conn):
    while True:
        try:
            # Receive data from the client, max buffer size is 4096 bytes
            data = conn.recv(4096)
            if not data:
                break  # If no data is received, break the loop
            # Send data to the other client
            other_conn.sendall(data)
        except ConnectionResetError as e:
            break  # If the client is disconnected, break the loop
    conn.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 9999
    server_socket.bind((host, port))
    server_socket.listen(2)

    print(green_text(f"Server started on {host}:{port}. Waiting for two clients to connect."))

    conn1, addr1 = server_socket.accept()
    print(green_text(f"First client connected: {addr1}"))

    conn2, addr2 = server_socket.accept()
    print(green_text(f"Second client connected: {addr2}"))

    # Start a new thread to handle communication for each client
    threading.Thread(target=client_thread, args=(conn1, conn2)).start()
    threading.Thread(target=client_thread, args=(conn2, conn1)).start()
if __name__ == '__main__':
    while True:
        start_server()
        print(blue_text('Server closed.'))