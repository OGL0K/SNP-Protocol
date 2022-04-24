import socket
import json

IP = socket.gethostbyname(socket.gethostname())
HOST = 5151
BUFFER_SIZE = 1024
ADDRESS = (IP, HOST)
FORMAT = 'utf-8'


message = {'id': '<REQUEST_ID>' ,'type': 'SEND', 'body': {'id': '214df-dsf-sdfq324-sdf-wdnsjdn', 'method': 'GET', 'path': 'www.google.com', 'parameters': '', 'Timeout': 1}}, {'Type': 'AUTH', 'Body': {'token': 'og00209'}}
json_message = json.dumps(message)


UDPClientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UDPClientSocket.settimeout(5)

try:

    def sendRequest():
        UDPClientSocket.sendto(json_message.encode(FORMAT), ADDRESS)

    def receiveResponse():
        ServerResponse = UDPClientSocket.recvfrom(BUFFER_SIZE)
        msg = f"{(ServerResponse[0].decode(FORMAT))}"
        print(msg)
    
    sendRequest()
    receiveResponse()

except socket.timeout:
    print('Timeout.')