from lib2to3.pgen2 import token
import socket
import json
import string
import random
import textwrap
from time import sleep

letters_digits = string.ascii_lowercase + string.digits
id = ''.join(random.choice(letters_digits) for i in range(8)) + "-"  +  ''.join(random.choice(letters_digits) for i in range(4)) + "-"  +  ''.join(random.choice(letters_digits) for i in range(4)) + "-"  +  ''.join(random.choice(letters_digits) for i in range(12))

IP = socket.gethostbyname(socket.gethostname())
HOST = 5151
BUFFER_SIZE = 1000000
ADDRESS = (IP, HOST)
FORMAT = 'utf-8'

UDPClientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UDPClientSocket.settimeout(50)

try:
    type = input('Please enter your type: ')
    authtoken = input('Please enter a token: ')
except socket.timeout:
    print('Timeout.')

send_request = {'id': id ,'type': 'SEND', 'body': {'method': 'GET', 'path': 'https://www.google.com', 'queryParameters': '', 'body': {'username': 'og00209'}, 'Timeout': 1000}},{'Type': 'AUTH', 'Body': {'token': 'og00209'}} 
auth_request = {'Type': 'AUTH', 'Body': {'token': authtoken}}



def sendRequest(send_request, UDPClientSocket):
    
    json_message = json.dumps(send_request)
    packet_list = textwrap.wrap(json_message, 1024)
    
    try:
       
     
        
        for i in range(len(packet_list)):
            packet = {"id": id, "packetNumber": i+1, "totalPackets": len(packet_list), "payloadData": packet_list[i] }
            encodedpacket = json.dumps(packet).encode()
            UDPClientSocket.sendto(encodedpacket, ADDRESS)
            
    except socket.timeout:
        print('Timeout.')

sendRequest(send_request, UDPClientSocket)

def receiveRespond():
    try:   
        while(True):
            
            ServerResponse = UDPClientSocket.recvfrom(BUFFER_SIZE)
            msg = f"{(ServerResponse[0].decode(FORMAT))}"
            print(msg)
            sleep(2)
            
    except socket.timeout:
        print('Timeout.')

receiveRespond()
