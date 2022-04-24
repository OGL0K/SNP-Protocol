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

authtoken = 'og00209'

json_error = { 'Success': False, 'Status': 401, 'Payload': { 'ERROR': 'UNAUTHORIZED', 'MESSAGE': "Used an unauthorized token in the request." } }
error = json.dumps(json_error)
error_bytes = str.encode(error)

authpass_json = {'success': True, 'status': 200, 'payload': { 'Message': 'Authentication successful' }}
authpass = json.dumps(authpass_json)
authpass_bytes = str.encode(authpass)

bad_request_json = { 'success': False, 'status': 400, 'payload': { 'error': 'BAD_REQUEST', 'message': 'Incorrect properties in request'} } 
bad_request = json.dumps(bad_request_json)
bad_request_bytes = str.encode(bad_request)




UDPServer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UDPServer.bind(ADDRESS)
UDPServer.settimeout(20)
print("Server up and listening")


try: 
       while(True):
                bytesAddressPair = UDPServer.recvfrom(BUFFER_SIZE)
                message = bytesAddressPair[0].decode(FORMAT)
                address = bytesAddressPair[1]

                clientMsg = "Request from Client: {}".format(message)
                clientIP  = "Client IP Address: {}".format(address)

                print(clientMsg)
                print(clientIP)
                request_json = json.loads(message)
                        
                
                try:
                        connection = http.client.HTTPSConnection(request_json[0]['body']['path'], timeout = request_json[0]['body']['Timeout'])
                        if(request_json[0]['body']['path'] == None or request_json[1]['Body']['token'] == None):
                                continue
                                     
                except KeyError:
                        UDPServer.sendto(bad_request_bytes, address)
                        break

                if(request_json[1]['Body']['token'] == ''):
                        connected_clients = {'Address': address[0], 'login': 0}
                        connection.request(request_json[0]['body']['method'], request_json[0]['body']['parameters'])
                                
                        print(connected_clients)
                
                elif(request_json[1]['Body']['token'] != authtoken):
                        UDPServer.sendto(error_bytes, address)
                        print("Authentication token is incorrect. Please use a correct token.")
                        

                elif(request_json[1]['Body']['token'] == authtoken):
                        connection.request(request_json[0]['body']['method'], request_json[0]['body']['parameters'])

                        response = connection.getresponse()

                        success_json = {'id': request_json[0]['body']['id'] ,'success': True, 'status': 200, 'payload': { 'content': str(response.read()) ,'requests': None }}
                        success_str = json.dumps(success_json) 
                        success_bytes = str.encode(success_str)

                        

                        
                        
                        
except socket.timeout:
        print("405 - Server Timeout.")