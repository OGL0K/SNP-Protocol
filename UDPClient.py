import socket
import json
import string
import random

letters_digits = string.ascii_lowercase + string.digits
id = ''.join(random.choice(letters_digits) for i in range(8)) + "-"  +  ''.join(random.choice(letters_digits) for i in range(4)) + "-"  +  ''.join(random.choice(letters_digits) for i in range(4)) + "-"  +  ''.join(random.choice(letters_digits) for i in range(12))

IP = socket.gethostbyname(socket.gethostname())
HOST = 5151
BUFFER_SIZE = 1000000
ADDRESS = (IP, HOST)
FORMAT = 'utf-8'


message = {'id': id ,'type': 'SEND', 'body': {'method': 'GET', 'path': 'https://www.google.com', 'queryParameters': '', 'body': {'username': 'og00209'}, 'Timeout': 1000}}, {'Type': 'AUTH', 'Body': {'token': ''}}
json_message = json.dumps(message)
json_bytes = str.encode(json_message)


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