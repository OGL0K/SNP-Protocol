import socket
import json

from Server import HEADER


IP = socket.gethostbyname(socket.gethostname())
PORT = 5151
HEADER = 64
ADDRESS = (IP, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT".encode(FORMAT)

info = {'type': 'SEND', 'body': {'method': 'GET', 'path': 'www.google.com', 'parameters': {}, 'Timeout': 1000}}
datajson = json.dumps(info).encode(FORMAT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDRESS)
print(f"Conected to the server.")

def send(msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)
    print(client.recv(2048).decode(FORMAT))

send(datajson)


    



