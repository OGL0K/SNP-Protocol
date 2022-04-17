from ast import While
import io
import sys
import json
import socket
import http.client
import threading
import flask

from urllib import request, response
from multiprocessing import connection


IP = socket.gethostbyname(socket.gethostname())
PORT = 5151
HEADER = 64
ADDRES = (IP, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

error = {"Success": True, "Status": 405, "Payload": {"ERROR": "SEVER_TIMEOUT", "MESSAGE": "The server's request timed out."}}
strerror = str(error)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
server.bind((ADDRES))

def client_handle(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    connected = True
    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            msg = conn.recv(msg_length).decode(FORMAT)
            if msg == DISCONNECT_MESSAGE:
                connected = False

            print(f"[{addr}] {msg}")

    conn.close()

def start():
    server.listen()
    print(f"[LISTENING] Server is listening on {IP}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=client_handle, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


print("[STARTING] Server is starting...")
start()


