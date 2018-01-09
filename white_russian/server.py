#!/usr/bin/python3 -u

from protocol import RatchetProtocol
from pickle import load
import random
import os
import sys

#this is a reresentative sample of text messages exchanged via messaging apps:
messages = [
    'Hi',
    'haha',
    'lol',
    'rofl',
    ':)',
    ':-)',
    ':D',
    #'FreeDeniz', # removed, because it's Twitter (and not an IM App)
]

def get_random_message():
    v = random.random()
    if v < 0.75:
        return random.choice(messages)
    elif v < 0.99:
        return 'https://xkcd.com/' + str(random.randint(1, 1933))
    else:
        return 'https://www.youtube.com/user/thejuicemedia'


pow_hardness = 2**22

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    if 0 != os.system('python3 pow.py ask {}'.format(pow_hardness)):
        exit(1)
    
    with open("flag.txt", "r") as f:
        FLAG = f.read()
    with open("private-data/state_alice.pickle", "rb") as f:
        alices_state = load(f)
    
    while True:
        message = sys.stdin.buffer.readline(1024).strip()
        try:
            message = alices_state.on_recv_message(message)
        except Exception as e:
            print("Error: " + str(e))
            break
        
        if message == "Would you send me the flag, please?":
            response = FLAG
        elif message == "exit" or message == "quit":
            exit(0)
        else:
            response = get_random_message()
        response = alices_state.prepare_send_message(response)
        sys.stdout.buffer.write(response + b"\n")
        sys.stdout.buffer.flush()
