import socket
import json

ip = "127.0.0.1"
port = 65432

info = {'type': 'SEND', 'body': {'method': 'GET', 'path': 'www.google.com', 'parameters': {}, 'Timeout': 1000}}

datajson = json.dumps(info)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print("Creating a socket...")
    print("Socket has been created.")
    s.connect((ip, port))
    print(f"Conected to the server.")
    s.sendall(bytes(datajson,encoding="utf-8"))
    print("JSON has been sent.")
    data = s.recv(1024)
    print({data})

print("Closing socket...")
s.close()
    



