#!/usr/bin/env python

import socket
import struct
import os

def main():
    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv.bind(('0.0.0.0', 12345))
    serv.listen(5)

    while True:
        conn, addr = serv.accept()
        from_client = ''
        
        while True:
            data = conn.recv(4096)
            if not data: break
            from_client += data
            
        print("Received data length = " + str(len(from_client)))
        conn.close()

if __name__ == '__main__':
    main()