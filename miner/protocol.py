#!/usr/bin/python3

# imports
from hashlib import pbkdf2_hmac, sha256
from random import SystemRandom
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long
import hmac
from miner import SignatureScheme
from base64 import b64encode, b64decode
from pickle import load

# constants
MODULUS = 26207223429869024417325222004741798995484843826774732444649404688036691581747054368912065044174281939502631344749843507980935845831279174906073092506393027974068576208317792107171477091826933945351324744079066803739911938262595927526991077769548676137810116097365024690973974016330454690809669463985536575739435587149760216049056617838572642410118050208322969087968435544740804445476570011158922225564009524299984227099580854627489098787771990431258004605321700924493450187542280654597162115504051949610710783157312954896554227595133482197009811348467687204497789941689368873095508440824889534148778750001002122406303
GROUP_ORDER = (MODULUS - 1) // 2
GENERATOR = 25

# helpers
def encode_int(i, len):
    return encode_bytes(long_to_bytes(i, len))
def decode_int(bytes):
    return bytes_to_long(decode_bytes(bytes))
def encode_bytes(bytes):
    return b64encode(bytes)
def decode_bytes(bytes):
    return b64decode(bytes)

# core functionality
class RatchetProtocol:
    
    def __init__(self, local_sig_scheme, remote_sig_scheme, generator, group_order, modulus):
        
        self.local_sig_scheme = local_sig_scheme
        self.remote_sig_scheme = remote_sig_scheme
        
        self.random = SystemRandom()
        self.generator = generator
        self.group_order = group_order
        self.modulus = modulus
        
        self.remote_public_element = None
        self._new_private_element()
        
        self.received_message_ctr = 0
        self.sent_message_ctr = 0
        self.received_messages = dict()
    
    def _new_private_element(self):
        self.private_exponent = self.random.randrange(1, self.group_order)
        self.public_element = pow(self.generator, self.private_exponent, self.modulus)
    
    def _symmetric_key(self, remote_element):
        key = pow(remote_element, self.private_exponent, self.modulus)
        key = pbkdf2_hmac('sha256', encode_int(key, 256), b'SALT_FOR_34C3CTF', 256)
        return key
    
    def _encrypt_message(self, message):
        
        self._new_private_element()
        
        enc_key = self._symmetric_key(self.remote_public_element)
        iv = self.random.randrange(pow(2, 128))
        ctr = Counter.new(128, initial_value=iv)
        
        cipher = AES.new(enc_key, AES.MODE_CTR, counter=ctr)
        ciphertext = cipher.encrypt(message.encode())
        return self.public_element, iv, ciphertext
    
    def _decrypt_message(self, remote_element, iv, ciphertext):
        
        enc_key = self._symmetric_key(remote_element)
        ctr = Counter.new(128, initial_value=iv)
        cipher = AES.new(enc_key, AES.MODE_CTR, counter=ctr)
        
        plaintext = cipher.decrypt(ciphertext).decode()
        return plaintext
    
    def prepare_send_message(self, message):
        
        public_element, iv, ciphertext = self._encrypt_message(message)
        signed_data = encode_int(public_element, 256) + b"|" + encode_int(iv, 16) + b"|" + encode_bytes(ciphertext)
        signature = self.local_sig_scheme.sign_new(signed_data)
        data = signed_data + b"|" + encode_int(signature, 256)
        
        self.sent_message_ctr += 1
        
        return data
        
    def on_recv_message(self, message):
        
        # check signature
        signed_data, signature = message.rsplit(b"|", 1)
        id = self.received_message_ctr + 1
        dict_copy = self.received_messages.copy()
        dict_copy[id] = signed_data
        signature_valid = self.remote_sig_scheme.verify(dict_copy, decode_int(signature))
        if not signature_valid: raise ValueError("invalid signature")
        
        # save and decrypt message
        self.received_messages[id] = signed_data
        remote_element, iv, ciphertext = signed_data.split(b"|")
        self.remote_public_element = decode_int(remote_element)
        plaintext = self._decrypt_message(self.remote_public_element, decode_int(iv), decode_bytes(ciphertext))
        
        self.received_message_ctr += 1
        
        return plaintext
    
    def __getstate__(self):
        """Called when this object is pickled: skip pickling self.random."""
        args = dict(self.__dict__) # copy self.__dict__
        del args['random']
        return args
    
    def __setstate__(self, state):
        """Called when this object is unpickled: restore all data and self.random."""
        self.__dict__ = state
        self.random = SystemRandom()

