import http.client
import json
import socket
from urllib import response

from requests import request

IP = socket.gethostbyname(socket.gethostname())
HOST = 5151
BUFFER_SIZE = 1024
ADDRESS = (IP, HOST)
FORMAT = 'utf-8'
json_error = { 'Success': True, 'Status': 405, 'Payload': { '“ERROR”': '“SEVER_TIMEOUT”', '“MESSAGE”': '“The server’s request timed out.”' } }
error = json.dumps(json_error)
error_bytes = str.encode(error)
UDPServer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UDPServer.bind(ADDRESS)
UDPServer.settimeout(10)
print("Server up and listening")

try:
       while(True):
        
                bytesAddressPair = UDPServer.recvfrom(BUFFER_SIZE)
                message = bytesAddressPair[0].decode(FORMAT)
                address = bytesAddressPair[1]

                clientMsg = "Message from Client: {}".format(message)
                clientIP  = "Client IP Address: {}".format(address)
    
                print(clientMsg)
                print(clientIP)

                my_json = json.loads(message)
                connection = http.client.HTTPSConnection(my_json['body']['path'], timeout = my_json['body']['Timeout'])
                try:
                        connection.request(my_json['body']['method'], my_json['body']['parameters'])
                except connection.timeout as st:
                        print('406 – Request Timeout.')
                        UDPServer.sendto(error_bytes, address)
                else:
                        response = connection.getresponse()
                        print("Status: {} Reason: {}".format(response.status, response.reason))
                        strresponse = "Status: {} Reason: {}".format(response.status, response.reason)
        
                        bytesToSend = str.encode(strresponse)

                        # Sending a reply to client
                        UDPServer.sendto(bytesToSend, address)

except socket.timeout:
        print("405 - Server Timeout.")