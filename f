import socket
import threading

PORT = 8080


def receive_messages(sock):
    while True:
        try:
            data = sock.recv(1024).decode()
            if not data:
                break
            print(f"\nReceived message:\n{data}")
        except:
            break


def send_message(sock, username):
    while True:
        receiver = input("Send message to: ")
        message = input("Enter message: ")
        if receiver == username:
            print("You can't send a message to yourself.")
            continue
        request = f"SMP 1.0\nACTION: SEND\nTO: {receiver}\nFROM: {username}\nLENGTH: {len(message)}\n\n{message}"
        sock.send(request.encode())
        response = sock.recv(1024).decode()
        print(f"Server response:\n{response}")


def main():
    HOST = input("Enter server IP address: ")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((HOST, PORT))
        except ConnectionRefusedError:
            print(f"Unable to connect to {HOST}:{PORT}. Make sure the server is running.")
            return

        username = input("Enter your username: ")

        # Connect to server
        connect_request = f"SMP 1.0\nACTION: CONNECT\nFROM: {username}\n"
        client_socket.send(connect_request.encode())
        response = client_socket.recv(1024).decode()
        print(f"Server response:\n{response}")

        # Start threads for sending and receiving messages
        threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()
        send_message(client_socket, username)


if __name__ == "__main__":
    main()



import socket
import threading

HOST = '0.0.0.0'  # This allows connections from any IP
PORT = 8080

clients = {}

def handle_client(conn, addr):
    username = None
    while True:
        try:
            data = conn.recv(1024).decode()
            if not data:
                break

            lines = data.split('\n')
            headers = {}
            message = ""
            for line in lines:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key] = value
                else:
                    message = line

            action = headers.get('ACTION')
            sender = headers.get('FROM')
            receiver = headers.get('TO')

            if action == 'CONNECT':
                username = sender
                clients[username] = conn
                response = "SMP 1.0\nSTATUS: OK\nMESSAGE: Connected successfully\n"
            elif action == 'SEND':
                if receiver in clients:
                    clients[receiver].send(
                        f"SMP 1.0\nACTION: RECEIVE\nFROM: {sender}\nLENGTH: {len(message)}\n\n{message}".encode())
                    response = "SMP 1.0\nSTATUS: OK\nMESSAGE: Message delivered successfully\n"
                else:
                    response = "SMP 1.0\nSTATUS: ERROR\nMESSAGE: Recipient not found\n"
            else:
                response = "SMP 1.0\nSTATUS: ERROR\nMESSAGE: Invalid action\n"

            conn.send(response.encode())
        except Exception as e:
            print(f"Error: {e}")
            break

    if username in clients:
        del clients[username]
    conn.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server started on {HOST}:{PORT}")
    print(f"Server's IP address: {socket.gethostbyname(socket.gethostname())}")

    while True:
        conn, addr = server_socket.accept()
        print(f"New connection from {addr}")
        threading.Thread(target=handle_client, args=(conn, addr)).start()
