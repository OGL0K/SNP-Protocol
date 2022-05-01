import json
import socket
import requests
import textwrap

IP = socket.gethostbyname(socket.gethostname())
HOST = 5151
BUFFER_SIZE = 1024
ADDRESS = (IP, HOST)
authtoken = 'og00209' 


UDPServer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UDPServer.bind(ADDRESS)
print("Server is up and listening...")

def Respond(respond, UDPServer):
    
        json_respond = json.dumps(respond)
        packet_list = textwrap.wrap(json_respond, 1024)

        for i in range(len(packet_list)):
            respond_packet = {"id": respond['id'], "packetNumber": i+1, "totalPackets": len(packet_list), "payloadData": packet_list[i]}
            print(f'Packet size: {len(packet)}')
            encodedpacket = json.dumps(respond_packet).encode()
            UDPServer.sendto(encodedpacket, address)

def Auth(request_json, address):
        
        try:
                if(request_json['body']['token'] == None):
                        return None
        except KeyError:
                bad_request_json = {'id': request_json['id'], 'success': False, 'status': 400, 'payload': { 'error': 'BAD_REQUEST', 'message': 'You have made a bad request'}} 
                bad_request = json.dumps(bad_request_json)
                bad_request_bytes = str.encode(bad_request)
                UDPServer.sendto(bad_request_bytes, address)
                return None

        if(request_json['body']['token'] == authtoken):
                authenticatedClients[address] = {'requests': None, 'authenticated': False}
                authenticated = True
                authpass_json = {'id': request_json['id'], 'success': True, 'status': 200, 'payload': { 'Message': 'Authentication successful'}}
                authenticatedClients[address]['authenticated'] = authenticated
                Respond(authpass_json, UDPServer)

        elif(request_json['body']['token'] != authtoken):
                json_error = {'id': request_json['id'], 'success': False, 'Status': 401, 'payload': { 'content': {'ERROR': 'UNAUTHORIZED', 'MESSAGE': 'Could not authenticate using your authentication token' }}}
                Respond(json_error, UDPServer)
                

def HTTPRequest(request_json, address): 

        try:
                if(request_json['type'] == None or request_json['body']['path'] == None ):
                        return None
                        
        except KeyError:
                bad_request_json = {'id': request_json['id'], 'success': False, 'status': 400, 'payload': { 'error': 'BAD_REQUEST', 'message': 'You have made a bad request'}} 
                Respond(bad_request_json, UDPServer)
                return None

        if(authenticatedClients == {}):
                if(request_json['body']['method'] == 'GET'):
                        try:
                                if(nonauthClient[address] -1 < 1):
                                        no_request_json = {'id': request_json['id'], 'success': False, 'Status': 403, 'payload': { 'content': {'ERROR': 'UNAUTHORISED_REQUEST', 'message': 'You have reached your request limit' }}}
                                        Respond(no_request_json, UDPServer)
                                else:
                                        r = requests.get(request_json['body']['path'], timeout = request_json['body']['Timeout'])
                                        
                                        if(r.status_code == requests.codes.ok):
                                                success = True

                                        else:
                                                success = False
                                
                                        success_json = {'id': request_json['id'] , 'success': success, 'status': r.status_code, 'payload': { 'content': str(r.text) ,'requests': nonauthClient[address] - 1}}
                                        Respond(success_json, UDPServer)
                                

                        except requests.exceptions.Timeout as e:
                                print(e)
                                timeout_json = {'id': request_json['id'], 'status': 408,  'success': False, 'payload': { 'content': { 'error': 'TIMEOUT_ERROR', 'message': 'Your request has timed out.'}}}
                                Respond(timeout_json, UDPServer)
                                 
                        except NameError as e:
                                print(e)
                                internalerr_json = {'id': request_json['id'], 'status': 405,  'success': False, 'payload': { 'content': { 'error': 'INTERNAL_SERVER_ERROR', 'message': 'There was a problem when processing your request.'}}}
                                Respond(internalerr_json, UDPServer)

                        except TypeError as e:
                                print(e)
                                internalerr_json = {'id': request_json['id'], 'status': 405,  'success': False, 'payload': { 'content': { 'error': 'INTERNAL_SERVER_ERROR', 'message': 'There was a problem when processing your request.'}}}
                                Respond(internalerr_json, UDPServer)
                
                elif(request_json['body']['method'] == 'POST'):

                        try:
                                if(nonauthClient[address] -1 < 1):
                                        no_request_json = {'id': request_json['id'], 'success': False, 'Status': 403, 'payload': { 'content': {'ERROR': 'UNAUTHORISED_REQUEST', 'message': 'You have reached your request limit' }}}
                                        Respond(no_request_json, UDPServer)
                                else:
                                        r = requests.post(request_json['body']['path'], data = request_json['body']['body']['username'] , timeout = request_json['body']['Timeout'])
                                        
                                        if(r.status_code == requests.codes.ok):
                                                success = True

                                        else:
                                                success = False
                                        
                                        success_json = {'id': request_json['id'] , 'success': success, 'status': r.status_code, 'payload': { 'content': str(r) ,'requests': nonauthClient[address] - 1}}
                                        Respond(success_json, UDPServer)
                                


                        except requests.exceptions.Timeout as e:
                                print(e)
                                timeout_json = {'id': request_json['id'], 'status': 408,  'success': False, 'payload': { 'content': { 'error': 'TIMEOUT_ERROR', 'message': 'Your request has timed out.'}}}
                                Respond(timeout_json, UDPServer)
                        
                        except NameError as e:
                                print(e)
                                internalerr_json = {'id': request_json['id'], 'status': 405,  'success': False, 'payload': { 'content': { 'error': 'INTERNAL_SERVER_ERROR', 'message': 'There was a problem when processing your request.'}}}
                                Respond(internalerr_json, UDPServer)

                        except TypeError as e:
                                print(e)
                                internalerr_json = {'id': request_json['id'], 'status': 405,  'success': False, 'payload': { 'content': { 'error': 'INTERNAL_SERVER_ERROR', 'message': 'There was a problem when processing your request.'}}}
                                Respond(internalerr_json, UDPServer)

                        
        elif(authenticatedClients[address]['authenticated'] == True):
                if(request_json['body']['method'] == 'GET'):
                        try:
                                        
                                r = requests.get(request_json['body']['path'], timeout = request_json['body']['Timeout'])
                                
                                if(r.status_code == requests.codes.ok):
                                        success = True

                                else:
                                        success = False
                                
                                success_json = {'id': request_json['id'] , 'success': success, 'status': r.status_code, 'payload': { 'content': str(r.text) ,'requests':authenticatedClients[address]['requests']}}
                                Respond(success_json, UDPServer)
                                
                        except requests.exceptions.Timeout as e:
                                print(e)
                                timeout_json = {'id': request_json['id'], 'status': 408,  'success': False, 'payload': { 'content': { 'error': 'TIMEOUT_ERROR', 'message': 'Your request has timed out.'}}}
                                Respond(timeout_json, UDPServer)

                        except NameError as e:
                                print(e)
                                internalerr_json = {'id': request_json['id'], 'status': 405,  'success': False, 'payload': { 'content': { 'error': 'INTERNAL_SERVER_ERROR', 'message': 'There was a problem when processing your request.'}}}
                                Respond(internalerr_json, UDPServer)

                        except TypeError as e:
                                print(e)
                                internalerr_json = {'id': request_json['id'], 'status': 405,  'success': False, 'payload': { 'content': { 'error': 'INTERNAL_SERVER_ERROR', 'message': 'There was a problem when processing your request.'}}}
                                Respond(internalerr_json, UDPServer)
                                

                elif(request_json['body']['method'] == 'POST'):

                        try:

                                r = requests.post(request_json['body']['path'], data = request_json['body']['body']['username'] , timeout = request_json['body']['Timeout'])
                                
                                if(r.status_code == requests.codes.ok):
                                        success = True

                                else:
                                        success = False
                                
                                success_json = {'id': request_json['id'] , 'success': success, 'status': r.status_code, 'payload': { 'content': str(r) ,'requests': authenticatedClients[address]['requests']}}
                                Respond(success_json, UDPServer)

                        except requests.exceptions.Timeout as e:
                                print(e)
                                timeout_json = {'id': request_json['id'], 'status': 408,  'success': False, 'payload': { 'content': { 'error': 'TIMEOUT_ERROR', 'message': 'Your request has timed out.'}}}
                                Respond(timeout_json, UDPServer)

                                print('Timeout')

                        except NameError as e:
                                print(e)
                                internalerr_json = {'id': request_json['id'], 'status': 405,  'success': False, 'payload': { 'content': { 'error': 'INTERNAL_SERVER_ERROR', 'message': 'There was a problem when processing your request.'}}}
                                Respond(internalerr_json, UDPServer)

                        except TypeError as e:
                                print(e)
                                internalerr_json = {'id': request_json['id'], 'status': 405,  'success': False, 'payload': { 'content': { 'error': 'INTERNAL_SERVER_ERROR', 'message': 'There was a problem when processing your request.'}}}
                                Respond(internalerr_json, UDPServer)
try:         
        FORMAT = 'utf-8'
        packets = {}
        authenticatedClients = {}
        nonauthClient = {}
        while(True):
                
                
                bytesAddressPair = UDPServer.recvfrom(BUFFER_SIZE)
                packet = bytesAddressPair[0].decode(FORMAT)
                address = bytesAddressPair[1]
                request_json = json.loads(packet)
                id = request_json['id']
                clientIP  = "Client IP Address: {}".format(address)
                print(clientIP)
        
                if address not in nonauthClient:
                        nonauthClient[address] = 10
                
                else:
                        nonauthClient[address] -= 1


                if id not in packets:
                        packets[id] = {request_json['packetNumber']: request_json['payloadData']}
                else:
                        packets[id][request_json['packetNumber']] = request_json['payloadData']
                

                if len(packets[id]) == request_json['totalPackets']:
                        reassembled = ''
                        for i in range(len(packets[id])):
                                reassembled += packets[id][i+1]
                        print(f'REASSEMBLED PACKET: {reassembled}')

                        request = json.loads(reassembled)
                        
                        if(request['type'] == 'AUTH'):
                                Auth(request, address)
                                packets = {}

                        elif(request['type'] == 'SEND'):
                                HTTPRequest(request, address)
                                packets = {}
                        

except NameError as e:
        print(e)
        internalerr_json = {'id': request_json['id'], 'status': 405,  'success': False, 'payload': { 'content': { 'error': 'INTERNAL_SERVER_ERROR', 'message': 'There was a problem when processing your request.'}}}
        Respond(internalerr_json, UDPServer)

except TypeError as e:
        print(e)
        internalerr_json = {'id': request_json['id'], 'status': 405,  'success': False, 'payload': { 'content': { 'error': 'INTERNAL_SERVER_ERROR', 'message': 'There was a problem when processing your request.'}}}
        Respond(internalerr_json, UDPServer)
