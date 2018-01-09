#!/usr/bin/python3

from hashlib import sha256
from random import SystemRandom
from Crypto.Util.number import getPrime, GCD, inverse, bytes_to_long
import sys

########################################################################
########################## Utility Functions ###########################
########################################################################


def random_blum_integer(length, max_tries=100):

    """returns a randomly selected blum integer with approximately length
    bits, consisting of two prime number of approximately length / 2 bits.
    If max_tries is given and positive, it (weakly and indirectly)
    limits the number of attempts this method makes to find a blum integer."""

    tries = 0
    p = 0
    p_length = length // 2
    while p % 4 != 3 and (max_tries is None or tries < max_tries):
        p = getPrime(p_length)
        tries += 1
    q = 0
    q_length = length - p_length
    while q % 4 != 3 and (max_tries is None or tries < max_tries):
        q = getPrime(q_length)
        tries += 1

    if max_tries is None and tries >= max_tries:
        raise ValueError("couldn't find a blum integer.")

    return p * q, p, q


def random_non_trivial_unit(n, max_tries=100):
    r = SystemRandom()
    v = r.randint(2, n - 2)
    tries = 0
    while GCD(v, n) != 1 and (max_tries is None or tries < max_tries):
        v = r.randint(2, n - 2)
        tries += 1
        if max_tries is not None and tries >= max_tries:
            raise ValueError("could not find a random non-trivial unit")
    return v


class SecretKey(object):
    def __init__(self, n, max_version, hash_length, r, s):
        self.n = n
        self.version = 1
        self.max_version = max_version
        self.hash_length = hash_length
        self.r = r
        self.s = s

    def update(self):
        if self.version >= self.max_version:
            self.version = self.max_version + 1
            del self.r
            del self.s
        else:
            self.s = pow(self.s, 2**self.hash_length, self.n)
            self.r = pow(self.r, 2**self.hash_length, self.n)
            self.version += 1


    def __eq__(self, other):
        return self.n == other.n and \
                self.version == other.version and \
                self.max_version == other.max_version and \
                self.hash_length == other.hash_length and \
                self.r == other.r and \
                self.s == other.s
    def __str__(self):
        return "Secret Key, Version " + str(self.version) + "\n" + \
            "Modulus: " + str(self.n) + "\n" + \
            "r: " + str(self.r) + "\n" + \
            "s: " + str(self.s) + "\n"

class PublicKey(object):
    def __init__(self, n, max_version, hash_function, hash_length, y, u):
        self.n = n
        self.max_version = max_version
        self.hash_function = hash_function
        self.hash_length = hash_length
        self.y = y
        self.u = u

    def __str__(self):
        return self.__class__.__name__ + " object:\n" + \
            "Modulus n: " + str(self.n) + "\n" + \
            "Max Version: " + str(self.max_version) + "\n" + \
            "Length of Hash Values l: " + str(self.hash_length) + "\n" + \
            "y: " + str(self.y) + "\n" + \
            "u: " + str(self.u) + "\n"


class SignatureScheme(object):

    SecretKey = SecretKey
    PublicKey = PublicKey

    @classmethod
    def new(
        cls, bitlength=2048, max_version=512,
        hash_function=sha256, hash_length=256
    ):
        sk, pk = cls.keygen(bitlength, max_version, hash_function, hash_length)
        return cls(sk, pk)

    def __init__(self, sk, pk):
        self.sk, self.pk = sk, pk
        self.signature = 1

    @classmethod
    def keygen(cls, bitlength, max_version, hash_function, hash_length):
        n, p, q = random_blum_integer(bitlength)
        phi = (p-1)*(q-1)
        e = pow(2**hash_length, max_version + 1, phi)

        r = random_non_trivial_unit(n)
        y = inverse(pow(r, e, n), n)
        r = pow(r, 2**hash_length, n)

        s = random_non_trivial_unit(n)
        u = inverse(pow(s, e, n), n)
        s = pow(s, 2**hash_length, n)

        sk = cls.SecretKey(n, max_version, hash_length, r, s)
        pk = cls.PublicKey(n, max_version, hash_function, hash_length, y, u)
        return sk, pk

    def update(self):
        self.sk.update()

    @staticmethod
    def _binary(bytestring):
        result = []
        for b in bytestring:
            for i in range(7, -1, -1):
                result.append((b >> i) & 1)
        return result

    @classmethod
    def _hash(cls, hash_function, message, version, y):
        version = int(version)
        version = hex(version)
        if version[-1] in ["L", "l"]: # correct for Python 2 Weirdness
            version = version[0:-1]
        version = version.encode()
        y = hex(int(y))
        if y[-1] in ["L", "l"]: # correct for Python 2 Weirdness
            y = y[0:-1]
        y = y.encode()
        bytes = (version + b" " + y + b" " + message)
        hash_value = hash_function(bytes).digest()
        return bytes_to_long(hash_value)

    def hash(self, message):
        return self._hash(
            self.pk.hash_function,
            message,
            self.sk.version,
            self.pk.y
        )

    def _sign(self, message):

        if self.sk.version > self.sk.max_version:
            error_msg = "cannot sign message: " + \
                "The secret key has reached the end of its life time. " + \
                "Version {} of {}"
            error_msg = error_msg.format(self.sk.version, self.sk.max_version)
            raise ValueError(error_msg)

        hash = self.hash(message)

        return self.sk.r * pow(self.sk.s, hash, self.pk.n)


    def _sign_new_without_update(self, message):
        self.signature = (self.signature * self._sign(message)) % self.pk.n
        return self.signature

    def sign_new(self, message):
        sig = self._sign_new_without_update(message)
        self.update()
        return sig

    @classmethod
    def _verify(cls, pk, hash_function, messages, signature, versions=None):

        exponentiations_done = 0
        for version in sorted(messages.keys(), reverse=True):
            exponentiations_to_do = pk.max_version + 1 - exponentiations_done - version
            exp = pow(2**pk.hash_length, exponentiations_to_do)
            signature = pow(signature, exp, pk.n)
            signature = (signature * pk.y) % pk.n
            hash = cls._hash(hash_function, messages[version], version, pk.y)
            signature = (signature * pow(pk.u, hash, pk.n)) % pk.n
            exponentiations_done += exponentiations_to_do

        return signature == 1

    def verify(self, messages, signature):
        return self.__class__._verify(
            self.pk,
            self.pk.hash_function,
            messages,
            signature
        )
