import json
import socket
import requests

IP = socket.gethostbyname(socket.gethostname())
HOST = 5151
BUFFER_SIZE = 100000
ADDRESS = (IP, HOST)


UDPServer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UDPServer.bind(ADDRESS)
UDPServer.settimeout(20)
print("Server is up and listening...")

try:         
        FORMAT = 'utf-8'
        authtoken = 'og00209'
        connectedClients = {}
        
        while(True):
                
                bytesAddressPair = UDPServer.recvfrom(BUFFER_SIZE)
                message = bytesAddressPair[0].decode(FORMAT)
                address = bytesAddressPair[1]

               
                
                connectedClients[address[0]] = 0
                connectedClients[address[0]] += 1



                clientMsg = "Request from Client: {}".format(message)
                clientIP  = "Client IP Address: {}".format(address)
               

                print(clientIP)
                print(clientMsg)
                print(connectedClients)
                request_json = json.loads(message)
                        
                try:
                        if(request_json[0]['type'] == None or request_json[0]['body']['path'] == None or request_json[1]['Body']['token'] == None):
                                continue
                                     
                except KeyError:
                        bad_request_json = {'id': request_json[0]['id'], 'success': False, 'status': 400, 'payload': { 'error': 'BAD_REQUEST', 'message': 'You have made a bad request'}} 
                        bad_request = json.dumps(bad_request_json)
                        bad_request_bytes = str.encode(bad_request)
                        UDPServer.sendto(bad_request_bytes, address)
                        continue

                if(request_json[1]['Body']['token'] == ''):
                        
                        request = 10

                        if (request_json[0]['body']['method'] == 'GET'):
                                try:

                                        r = requests.get(request_json[0]['body']['path'], timeout = request_json[0]['body']['Timeout'])
                                        
                                        if(r.status_code == requests.codes.ok):
                                                success = True

                                        else:
                                                success = False
                                        
                                        authpass_json = {'id': request_json[0]['id'], 'success': True, 'status': 200, 'payload': { 'Message': 'Authentication successful'}}
                                        authpass = json.dumps(authpass_json)
                                        authpass_bytes = str.encode(authpass)

                                        success_json = {'id': request_json[0]['id'] , 'success': success, 'status': r.status_code, 'payload': { 'content': str(r) ,'requests': request}}
                                        success_str = json.dumps(success_json) 
                                        success_bytes = str.encode(success_str)

                                        UDPServer.sendto(success_bytes, address)

                                        if(request == 0):
                                                no_request_json = {'id': request_json[0]['id'], 'success': False, 'Status': 403, 'payload': { 'content': {'ERROR': 'UNAUTHORISED_REQUEST', 'message': 'You have reached your request limit' }}}
                                                no_request_str = json.dumps(no_request_json)
                                                no_request_bytes = str.encode(no_request_str)

                                                UDPServer.sendto(no_request_bytes, address)
                                               


                                except requests.exceptions.Timeout:
                                        timeout_json = {'id': request_json[0]['id'], 'status': 408,  'success': False, 'payload': { 'content': { 'error': 'TIMEOUT_ERROR', 'message': 'Your request has timed out.'}}}
                                        timeout_str = json.dumps(timeout_json)
                                        timeout_bytes = str.encode(timeout_str) 

                                        print('Timeout')
                        
                        

                elif(request_json[1]['Body']['token'] != authtoken):
                        json_error = {'id': request_json[0]['id'], 'success': False, 'Status': 401, 'payload': { 'content': {'ERROR': 'UNAUTHORIZED', 'MESSAGE': 'Could not authenticate using your authentication token' }}}
                        error = json.dumps(json_error)
                        error_bytes = str.encode(error)
                        UDPServer.sendto(error_bytes, address)
                        print("Authentication token is incorrect. Please use a correct token.")
                
                
                elif(request_json[1]['Body']['token'] == authtoken):

                        if (request_json[0]['body']['method'] == 'GET'):
                                try:

                                        r = requests.get(request_json[0]['body']['path'], timeout = request_json[0]['body']['Timeout'])
                                        
                                        if(r.status_code == requests.codes.ok):
                                                success = True

                                        else:
                                                success = False
                                        
                                        authpass_json = {'id': request_json[0]['id'], 'success': True, 'status': 200, 'payload': { 'Message': 'Authentication successful'}}
                                        authpass = json.dumps(authpass_json)
                                        authpass_bytes = str.encode(authpass)

                                        success_json = {'id': request_json[0]['id'] , 'success': success, 'status': r.status_code, 'payload': { 'content': str(r) ,'requests': None }}
                                        success_str = json.dumps(success_json) 
                                        success_bytes = str.encode(success_str)

                                        UDPServer.sendto(success_bytes, address)
                                
                                

                                except requests.exceptions.Timeout:
                                        timeout_json = {'id': request_json[0]['id'], 'status': 408,  'success': False, 'payload': { 'content': { 'error': 'TIMEOUT_ERROR', 'message': 'Your request has timed out.'}}}
                                        timeout_str = json.dumps(timeout_json)
                                        timeout_bytes = str.encode(timeout_str) 

                                        UDPServer.sendto(timeout_bytes, address)
                                        print('Timeout')
                                        

                        if (request_json[0]['body']['method'] == 'POST'):
                                try:

                                        r = requests.post(request_json[0]['body']['path'], timeout = request_json[0]['body']['Timeout'])
                                        
                                        if(r.status_code == requests.codes.ok):
                                                success = True

                                        else:
                                                success = False
                                        
                                        authpass_json = {'id': request_json[0]['id'], 'success': True, 'status': 200, 'payload': { 'Message': 'Authentication successful'}}
                                        authpass = json.dumps(authpass_json)
                                        authpass_bytes = str.encode(authpass)

                                        success_json = {'id': request_json[0]['id'] , 'success': success, 'status': r.status_code, 'payload': { 'content': str(r) ,'requests': None }}
                                        success_str = json.dumps(success_json) 
                                        success_bytes = str.encode(success_str)

                                        UDPServer.sendto(success_bytes, address)

                                except requests.exceptions.Timeout:
                                        timeout_json = {'id': request_json[0]['id'], 'status': 408,  'success': False, 'payload': { 'content': { 'error': 'TIMEOUT_ERROR', 'message': 'Your request has timed out.'}}}
                                        timeout_str = json.dumps(timeout_json)
                                        timeout_bytes = str.encode(timeout_str) 

                                        UDPServer.sendto(timeout_bytes, address)
                                             
except socket.timeout:
        print("405 - Server Timeout.")

except NameError as e:
        print(e)
        internalerr_json = {'id': request_json[0]['id'], 'status': 405,  'success': False, 'payload': { 'content': { 'error': 'INTERNAL_SERVER_ERROR', 'message': 'There was a problem when processing your request.'}}}
        internalerr_str = json.dumps(internalerr_json)
        internalerr_bytes = str.encode(internalerr_str) 

        UDPServer.sendto(internalerr_bytes, address)

except TypeError as e:
        print(e)
        internalerr_json = {'id': request_json[0]['id'], 'status': 405,  'success': False, 'payload': { 'content': { 'error': 'INTERNAL_SERVER_ERROR', 'message': 'There was a problem when processing your request.'}}}
        internalerr_str = json.dumps(internalerr_json)
        internalerr_bytes = str.encode(internalerr_str) 

        UDPServer.sendto(internalerr_bytes, address)