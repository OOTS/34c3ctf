#!/usr/bin/python2
import sys, time
import pickle
from miner import SignatureScheme
from sage.all import matrix, IntegerModRing
from protocol import GENERATOR, MODULUS, GROUP_ORDER, decode_int, RatchetProtocol
import socket, glob
import re
from pow import solve_proof_of_work

def solve_proof_of_work_on_socket(s):
    challenge = read_until(s, "Your response? ")
    regex = re.compile(b"Proof of work challenge: ([0-9_a-zA-Z]+)")
    challenge = regex.search(challenge).group(1)
    solution = solve_proof_of_work(challenge)
    s.sendall(str(solution).encode() + b"\n")

def sorted_glob(pattern):
    result = glob.glob(pattern)
    regex = re.compile(r'-(\d+)\.(txt|pickle)')
    sort_key = lambda filename: int(regex.search(filename).group(1))
    result.sort(key=sort_key)
    return result

def product(values, n):
    def multiply_mod_n(a, b):
        return (a * b) % n
    return reduce(multiply_mod_n, values, 1)

def read_until(socket, expected):
    buf = b""
    while not expected in buf:
        received = socket.recv(1)
        if received == b'': raise ValueError("can't read data on socket")
        buf += received
    return buf

def recover_secret_key(pk, messages, signatures):

    Zn = IntegerModRing(pk.n)

    aggregate_signatures = map(Zn, signatures)
    signatures = []
    prev = 1
    sig_scheme = SignatureScheme(None, pk)
    for i in xrange(0, len(aggregate_signatures)):
        signatures.append(aggregate_signatures[i] / prev)
        prev = aggregate_signatures[i]

    hash_function = pk.hash_function
    hash_length = pk.hash_length
    hashes = [[1] + sig_scheme._hash(hash_function, m, i, pk.y) for i, m in enumerate(messages, 1)]
    M = matrix(hashes)
    print("Computing transform...")
    H, T = M.hermite_form(transformation=True)
    assert(T*M == H)
    assert(is_identity(H))
    rows = T.rows()
    no_rows = len(rows)

    print("Projecting all signatures into the target epoch...")
    for i, s in enumerate(signatures):
        signatures[i] = pow(signatures[i], 2**(no_rows - i - 1), pk.n)

    print("Reconstructing the secret key values...")
    r = product([pow(signatures[j], rows[0][j]) for j in xrange(len(signatures))], pk.n)
    s = []
    for i in xrange(1, hash_length + 1):
        print(i)
        row = rows[i]
        h = product([pow(signatures[j], row[j]) for j in xrange(len(signatures))], pk.n)
        s.append(h)

    secret_key = SignatureScheme.SecretKey(int(pk.n), int(pk.max_version), hash_length, int(r), [int(e) for e in s])
    secret_key.version = len(signatures)

    return secret_key

def attack(target, target_pk, remote_pk, messages, signatures):

    try:
        with open("sk.pickle", "rb") as f:
            sk = pickle.load(f)
    except:
        sk = recover_secret_key(target_pk, messages, signatures)
        with open("sk.pickle", "wb") as f:
            pickle.dump(sk, f)
    print("Got the secret key.")

    sig_scheme = SignatureScheme(sk, target_pk)
    sig_scheme.signature = last_signature_b2a
    while(sk.version < target_epoch):
        sig_scheme.update()

    protocol_state = RatchetProtocol(
        sig_scheme, SignatureScheme(None, remote_pk),
        GENERATOR, GROUP_ORDER, MODULUS
    )
    protocol_state.received_message_ctr = len(messages_a2b)
    protocol_state.received_messages = dict(enumerate(messages_a2b, 1))
    protocol_state.remote_public_element = remote_base_element
    sig_scheme.sk.r = int(sig_scheme.sk.r)
    sig_scheme.sk.s = [int(e) for e in sig_scheme.sk.s]
    message = protocol_state.prepare_send_message(target_message)

    print("Message:")
    print(str(message))

    s = socket.create_connection(target)
    solve_proof_of_work_on_socket(s)
    print("Solved proof of work...")
    time.sleep(1)
    try:
        s.sendall(message + "\n")
        #s.shutdown(socket.SHUT_WR)
        response = read_until(s, "\n")
        print("Response:")
        print(response)
        flag = protocol_state.on_recv_message(response)
        return flag
    finally:
        s.close()

def is_identity(matrix):
    for i in range(matrix.nrows()):
        row = matrix.rows()[i]
        for j in range(matrix.ncols()):
            if i == j and row[j] != 1: return False
            if i != j and row[j] != 0: return False
    return True


if __name__ == "__main__":

    with open("public-data/alices_public_key.pickle", "rb") as f:
        alices_pk = pickle.load(f)

    with open("public-data/bobs_public_key.pickle", "rb") as f:
        bobs_pk = pickle.load(f)

    messages_a2b = []
    signatures_a2b = []
    for filename in sorted_glob("public-data/messages/a2b-*.txt"):
        with open(filename, "rb") as f:
            message = f.read()
        message, signature = message.rsplit("|", 1)
        messages_a2b.append(message)
        signatures_a2b.append(signature)

    messages_b2a = []
    signatures_b2a = []
    for filename in sorted_glob("public-data/messages/b2a-*.txt"):
        with open(filename, "rb") as f:
            message = f.read()
        message, signature = message.rsplit("|", 1)
        messages_b2a.append(message)
        signatures_b2a.append(decode_int(signature))

    sig_scheme = SignatureScheme(None, bobs_pk)
    target = (sys.argv[1], int(sys.argv[2]))
    target_epoch = len(messages_b2a) + 1
    target_message = "Would you send me the flag, please?"
    remote_base_element = decode_int(messages_a2b[-1].split("|")[0])
    last_signature_b2a = signatures_b2a[-1]
    flag = attack(target, bobs_pk, alices_pk, messages_b2a, signatures_b2a)
    print(flag)
