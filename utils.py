import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import Hash, SHA256


def one_of(sequence):
    return random.choice(sequence)


def hash_sha256(bytes_):
    digest = Hash(SHA256(), backend=default_backend())
    digest.update(bytes_)
    return digest.finalize()


def frame(word):
    return "▛▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀\n" \
           "▌  %s\n" \
           "▙▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄" % word
