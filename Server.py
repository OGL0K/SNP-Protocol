import io
import json
import socket
import http.client
import flask

from urllib import request, response
from multiprocessing import connection


proxy_ip = "127.0.0.1"
proxy_port = 65432

error = {"Success": True, "Status": 405, "Payload": {"ERROR": "SEVER_TIMEOUT", "MESSAGE": "The server's request timed out."}}

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:   
    print("Creating a socket...")
    print("Socket has been created.")
    s.bind((proxy_ip, proxy_port))
    s.listen()
    print("Listening socket...")
    conn, addr = s.accept()
        
    print(f"Got a connection from {addr}")
    data = conn.recv(1024)
    print(f"JSON has been recieved {data}")

    fix_bytes_value = data.replace(b"'", b'"')
    my_json = json.load(io.BytesIO(fix_bytes_value))

    try:
        connection = http.client.HTTPSConnection(my_json['body']['path'], timeout = my_json['body']['Timeout'])
        connection.request(my_json['body']['method'], '/')
    except connection.request.Timeout():
        conn.send(bytes(error, encoding= 'utf-8'))
     
    response = flask.Response(status=201)
    strvalue = str(response)
    print(f"Status: {response.status}")
    

    print("Sending response...")
    conn.send(bytes(strvalue, encoding= 'utf-8'))
    print("Request sent.")

print("Closing socket...")
s.close()

