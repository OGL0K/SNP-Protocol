import socket
import json

IP = socket.gethostbyname(socket.gethostname())
HOST = 5151
BUFFER_SIZE = 1024
ADDRESS = (IP, HOST)
FORMAT = 'utf-8'


json_message = {'type': 'SEND', 'body': {'method': 'GET', 'path': 'www.google.com', 'parameters': '/', 'Timeout': 1000}, 'Type': '‘AUTH’', 
'token': '‘AAAAAAAAAAAAAAAAAAAAAMLheAAAAAAA0%2BuSeid%2BULvsea4JtiGRiSDSJSI%3DEUifiRBkKG5E2XzMDjRfl76ZC9Ub0wnz4XsNiRVBChTYbJcE3F’' }

json_str = json.dumps(json_message)
bytesToSend = str.encode(json_str)

try:
    UDPClientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDPClientSocket.settimeout(5)
    UDPClientSocket.sendto(bytesToSend, ADDRESS)
    msgFromServer = UDPClientSocket.recvfrom(BUFFER_SIZE)
    msg = "Message from Server: {}".format(msgFromServer[0].decode(FORMAT))
    print(msg)
except socket.timeout:
    print("Client Timeout.")

