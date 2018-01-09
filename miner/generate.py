#!/usr/bin/python3

from protocol import GENERATOR, GROUP_ORDER, MODULUS
from protocol import RatchetProtocol, SignatureScheme
import random
from server import get_random_message
import pickle
import os

def save(obj, filename):
    with open(filename, "wb") as f:
        pickle.dump(obj, f, protocol=2)
    

if __name__ == "__main__":
    
    print("Generating keys...")
    alice_sig = SignatureScheme.new(2048)
    bob_sig = SignatureScheme.new(2048)
    alices_remote_sig = SignatureScheme(None, bob_sig.pk)
    bobs_remote_sig = SignatureScheme(None, alice_sig.pk)
    
    # set up the ratchet protocol instances
    alice_state = RatchetProtocol(alice_sig, alices_remote_sig, GENERATOR, GROUP_ORDER, MODULUS)
    bob_state = RatchetProtocol(bob_sig, bobs_remote_sig, GENERATOR, GROUP_ORDER, MODULUS)
    alice_state.remote_public_element = bob_state.public_element
    bob_state.remote_public_element = alice_state.public_element
    
    # create directories
    path = os.path.dirname(__file__)
    os.makedirs(os.path.join(path, "public-data/messages"), exist_ok = True)
    os.makedirs(os.path.join(path, "private-data/debug"), exist_ok = True)
    
    parties = [alice_state, bob_state]
    sender = 0
    print("Generating a random conversation...")
    for i in range(random.randrange(550, 650)):
        
        sender_proto = parties[sender]
        receiver_proto = parties[1 - sender]
        
        m = get_random_message()
        c = sender_proto.prepare_send_message(m)
        if sender == 0:
            filename = "public-data/messages/a2b-{}.txt".format(i)
            sk_filename = "private-data/debug/alices-key-{}.pickle".format(alice_state.local_sig_scheme.sk.version)
            with open(sk_filename, "wb") as f:
                pickle.dump(alice_state.local_sig_scheme.sk, f, protocol=2)
        else:
            filename = "public-data/messages/b2a-{}.txt".format(i)
            sk_filename = "private-data/debug/bobs-key-{}.pickle".format(bob_state.local_sig_scheme.sk.version)
            with open(sk_filename, "wb") as f:
                pickle.dump(alice_state.local_sig_scheme.sk, f, protocol=2)
        with open(filename, 'wb') as f:
            f.write(c)
        decrypted = receiver_proto.on_recv_message(c)
        print("{}: {}".format(i, decrypted))
        assert(decrypted == m)
        
        if random.random() < 0.5:
            # swap sender and receiver
            sender = sender ^ 1
        
    
    save(alice_state, "private-data/state_alice.pickle")
    save(bob_state, "private-data/state_bob.pickle")
    save(alice_sig.pk, "public-data/alices_public_key.pickle")
    save(bob_sig.pk, "public-data/bobs_public_key.pickle")
    with open("public-data/alices_public_key.txt", "w") as f:
        f.write(str(alice_sig.pk))
    with open("public-data/bobs_public_key.txt", "w") as f:
        f.write(str(bob_sig.pk))
