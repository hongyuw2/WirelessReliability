#!/usr/bin/env python

import socket
import sys
import string
import random

# CONST
MESSAGE_SIZE = 10000

def randStr(chars = string.ascii_uppercase + string.digits, N=10):
    return ''.join(random.choice(chars) for _ in range(N))

def main():

    if len(sys.argv) < 2:
        print('pass 1 argument: <destination>')
        exit(1)

    sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr = socket.gethostbyname(sys.argv[1])
    sender.connect((addr, 12345))
    
    msg = randStr(N=MESSAGE_SIZE)
    sender.send(msg)
    sender.close()

if __name__ == '__main__':
    main()