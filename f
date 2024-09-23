import socket
import threading

HOST = '0.0.0.0'  # Позволяет подключения с любого IP
PORT = 8080

clients = {}

def handle_client(conn, addr):
    username = None
    print(f"Подключен: {addr}")
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
            print(f"Ошибка: {e}")
            break

    if username in clients:
        del clients[username]
        print(f"{username} отключен.")
    conn.close()

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Сервер запущен на {HOST}:{PORT}")
        print(f"IP адрес сервера: {socket.gethostbyname(socket.gethostname())}")

        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
