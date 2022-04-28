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

def handlePacket(request_json, address): 

        global connectedClients
        try:
                if(request_json[0]['type'] == None or request_json[0]['body']['path'] == None or request_json[1]['Body']['token'] == None):
                        return None
                        
        except KeyError:
                bad_request_json = {'id': request_json[0]['id'], 'success': False, 'status': 400, 'payload': { 'error': 'BAD_REQUEST', 'message': 'You have made a bad request'}} 
                bad_request = json.dumps(bad_request_json)
                bad_request_bytes = str.encode(bad_request)
                UDPServer.sendto(bad_request_bytes, address)
                return None

        if(request_json[1]['Body']['token'] == ''):

                if address not in connectedClients:
                        connectedClients[address] = {'requests': 0, 'authenticated': False}
                        
                connectedClients[address]['request'] += 1

                print(connectedClients)
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

                                UDPServer.sendto(authpass_bytes, address)
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
                                
        
try:         
        FORMAT = 'utf-8'
        authtoken = 'og00209'
        
        connectedClients = {} 
        packets = {}
        while(True):

                bytesAddressPair = UDPServer.recvfrom(BUFFER_SIZE)
                packet = bytesAddressPair[0].decode(FORMAT)
                address = bytesAddressPair[1]
                request_json = json.loads(packet)
                id = request_json['id']

                if id not in packets:
                        packets[id] = { request_json['packetNumber']: request_json['payloadData']}
                else:
                        packets[id]['packetNumber'] = request_json['payloadData']

                if len(packets[id]) == request_json['totalPackets']:
                        reassembled = ''
                        for i in range(len(packets[id])):
                                reassembled += packets[id][i+1]
                        print(f'REASSEMBLED PACKET: {reassembled}')
                        handlePacket(json.loads(reassembled),address) 
                clientIP  = "Client IP Address: {}".format(address)
               
                print(clientIP)
                               
       
        
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
