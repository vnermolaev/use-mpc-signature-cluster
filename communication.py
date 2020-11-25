import base64
import json
import uuid
from enum import Enum

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.hashes import Hash, SHA256

from utils import hash_sha256


class Fail(Enum):
    KEY_GEN = 'KeyGen Failure'
    KEY_GET = 'Failed to retrieve key'
    KEY_REFRESH = 'Failed to refresh key'
    APPROVE = 'Approval Request Failure'
    SGN_GEN = 'Signature Generation Failure'
    SGN_WRONG_LENGTH = 'Incorrect Signature Length'
    SGN_VERIFICATION = 'Signature Verification Failure'
    NODE_OFFLINE = 'Node Unreachable'


def are_ready(urls):
    """
    Evaluates node readiness by requesting to generate a key with a random id.
    Node is not ready if it returns 500 "Node is not ready to process requests"
    :param urls: list of endpoints
    :return: true if none of the nodes responded 500
    """

    for url in urls:
        key_id = 'test-test-test-' + str(uuid.uuid4())
        params = {
            'signers': 2,
            'share_count': 2
        }
        try:
            print('Requesting %s/keys/%s/new' % (url, key_id))
            rsp = requests.post('%s/keys/%s/new' % (url, key_id), json=params)
        except:
            return Fail.NODE_OFFLINE

        if rsp.status_code == 500:
            print('%s: %s' % (url, rsp.text))
            return False

    return True


def generate_key(url, key_id, params):
    print('\nGenerating a key with id = ' + key_id)
    try:
        rsp = requests.post('%s/keys/%s/new' % (url, key_id), json=params)
    except:
        return Fail.NODE_OFFLINE

    if rsp.status_code != 200:
        print(rsp.text)
        return Fail.KEY_GEN

    key = rsp.json()
    print('Generated:\n' + json.dumps(key, indent=2))

    # Construct public key
    x = int.from_bytes(b64url_decode_without_padding(key['pub_key']['x']), 'big')
    y = int.from_bytes(b64url_decode_without_padding(key['pub_key']['y']), 'big')

    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1()).public_key(default_backend())


def get_key(url, key_id):
    print('\nRequesting key with id = ' + key_id)
    try:
        rsp = requests.get('%s/keys/%s' % (url, key_id))
    except:
        return Fail.NODE_OFFLINE

    if rsp.status_code != 200:
        print(rsp.text)
        return Fail.KEY_GET

    key = rsp.json()
    print('Received:\n' + json.dumps(key, indent=2))

    # Construct public key
    x = int.from_bytes(b64url_decode_without_padding(key['pub_key']['x']), 'big')
    y = int.from_bytes(b64url_decode_without_padding(key['pub_key']['y']), 'big')

    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1()).public_key(default_backend())


def get_key_raw(url, key_id):
    print('\nGetting RAW response on requesting key with id = ' + key_id)
    try:
        rsp = requests.get('%s/keys/%s' % (url, key_id))
    except:
        return Fail.NODE_OFFLINE

    if rsp.status_code != 200:
        print(rsp.text)
        return Fail.KEY_GET

    received = rsp.text.encode('utf-8')
    print('Received:')
    print(received)

    return received


def approve(urls, key_id, message):
    request = {'message': [i for i in hash_sha256(message)]}

    print('\nRequest to approve\n%s\nwith key_id = %s' % (json.dumps(request, indent=2), key_id))

    for url in urls:
        try:
            print('Requesting %s/keys/%s/approve' % (url, key_id))
            rsp = requests.post('%s/keys/%s/approve' % (url, key_id), json=request)
        except:
            return Fail.NODE_OFFLINE

        if rsp.status_code != 200:
            print(rsp.text)
            return Fail.APPROVE


def sign(url, key_id, message):
    request = {'message': [i for i in hash_sha256(message)]}

    print('\nRequest to sign\n%s\nwith key_id = %s' % (json.dumps(request, indent=2), key_id))
    try:
        print('Requesting %s/keys/%s/sign' % (url, key_id))
        rsp = requests.post('%s/keys/%s/sign' % (url, key_id), json=request)
    except:
        return Fail.NODE_OFFLINE

    if rsp.status_code != 200:
        print(rsp.text)
        return Fail.SGN_GEN

    signed = rsp.json()
    print('Received:\n' + json.dumps(signed, indent=2))

    signature = b64url_decode_without_padding(signed['signature'])

    if len(signature) != 64:
        return Fail.SGN_WRONG_LENGTH

    # Construct signature
    r = int.from_bytes(signature[:32], 'big')
    s = int.from_bytes(signature[32:], 'big')
    return utils.encode_dss_signature(r, s)


def refresh_key(url, key_id):
    print('\nRequest to refresh key_id = %s' % key_id)
    try:
        rsp = requests.put('%s/keys/%s/refresh' % (url, key_id))
    except:
        return Fail.NODE_OFFLINE

    if rsp.status_code != 200:
        print(rsp.text)
        return Fail.KEY_REFRESH


def attest_key(url, key_id):
    print('\nRequest to attest key with with key_id = %s' % key_id)
    try:
        rsp = requests.get('%s/keys/%s/attest' % (url, key_id))
    except:
        return Fail.NODE_OFFLINE

    if rsp.status_code != 200:
        print(rsp.text)
        return Fail.SGN_GEN

    signed = rsp.json()
    print('Received:\n' + json.dumps(signed, indent=2))

    signature = b64url_decode_without_padding(signed['signature'])

    if len(signature) != 64:
        return Fail.SGN_WRONG_LENGTH

    # Construct signature
    r = int.from_bytes(signature[:32], 'big')
    s = int.from_bytes(signature[32:], 'big')
    return utils.encode_dss_signature(r, s)


def b64url_decode_without_padding(s):
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(s)
