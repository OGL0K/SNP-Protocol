import socket
import json

IP = socket.gethostbyname(socket.gethostname())
HOST = 5151
BUFFER_SIZE = 1024
ADDRESS = (IP, HOST)
FORMAT = 'utf-8'


message = {'type': 'SEND', 'body': {'method': 'GET', 'path': 'www.google.com', 'parameters': '/', 'Timeout': 1}}, {'Type': 'AUTH', 'Body': {'token': 'og002098'}}
json_message = json.dumps(message)
json_bytes = str.encode(json_message)

try:
    UDPClientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDPClientSocket.settimeout(5)
    UDPClientSocket.sendto(json_bytes, ADDRESS)

    msgFromServer = UDPClientSocket.recvfrom(BUFFER_SIZE)
        
    msg = f"{(msgFromServer[0].decode(FORMAT))}"
    print(msg)

except socket.timeout:
    print("Client couldn't connect to server in time.")

