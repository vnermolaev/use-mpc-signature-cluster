#!/usr/bin/env python3
"""Python test script to help test a networked MPC cluster

This provides an easily readable example client, as well as verifying the
resulting public key and signature combination with a well-reviewed
cryptography implementation that is independent from the one used to generate
the data under test.
"""
import time

from communication import *

import sys
import uuid
import argparse

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from utils import one_of, hash_sha256, frame

ENVIRONMENTS = {
    'cluster': {
        'urls': ["http://20.73.233.190:%s" % port for port in
                 range(2601, 2604)],
        'parameters': {
            'signers': 3,
            'share_count': 3
        }
    }
}


def main():
    parser = argparse.ArgumentParser(description='Test full key lifecycle')
    parser.add_argument('--env', default='cluster', help='Environment for tests: `cluster`')
    parser.add_argument('--key', '-k', default=str(uuid.uuid4()), help='Specific key id, default value is a uuid')
    parser.add_argument('--message', '-m', default=uuid.uuid4(), help='Specific message to sign, default value is a uuid')
    args = parser.parse_args()

    args.message = str(args.message).encode('utf-8')

    print('Setup\nenvironment = %s\nkey id="%s"\nmessage="%s"' % (args.env, args.key, args.message))

    nodes = ENVIRONMENTS[args.env]['urls']
    params = ENVIRONMENTS[args.env]['parameters']

    print(frame("==== Node readiness ===="))
    proceed = False
    while not proceed:
        proceed = are_ready(nodes)
        if type(proceed) is Fail:
            sys.exit(proceed.value)
        if not proceed:
            s = 1
            print('Sleeping %s secs' % s)
            time.sleep(s)

    print("Nodes are ready")

    print(frame("==== Key generation ===="))
    # --- Generate a key.
    generated_pub_key = generate_key(one_of(nodes), args.key, params)
    if type(generated_pub_key) is Fail:
        sys.exit(generated_pub_key.value)

    # --- Retrieve a key.
    retrieved_pub_key = get_key(one_of(nodes), args.key)
    if type(retrieved_pub_key) is Fail:
        sys.exit(retrieved_pub_key.value)

    # --- Verify they are the same.
    assert \
        generated_pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo) == \
        retrieved_pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo), \
        "Generated and retrieved keys are different"

    pub_key = generated_pub_key

    print(frame("==== Signature ===="))
    # --- Approve to sign.
    approval = approve(nodes, args.key, args.message)
    if type(approval) is Fail:
        sys.exit(approval.value)

    # --- Sign.
    signature = sign(one_of(nodes), args.key, args.message)
    if type(signature) is Fail:
        sys.exit(signature.value)

    # --- Signature verifies.
    try:
        pub_key.verify(signature, args.message, ec.ECDSA(SHA256()))
        print("Signature has been verified successfully")
    except:
        sys.exit(Fail.SGN_VERIFICATION.value)

    print(frame("==== Attestation ===="))
    # --- Get attestation key.
    attestation_key = get_key(one_of(nodes), "attestation")
    if type(attestation_key) is Fail:
        sys.exit(attestation_key.value)

    # --- Get pub key as raw response.
    key_raw = get_key_raw(one_of(nodes), args.key)

    # --- Attest key.
    #    `attestation` is a signature on a sha256 hash of bytes of raw key response.
    attestation = attest_key(one_of(nodes), args.key)
    if type(attestation) is Fail:
        sys.exit(attestation.value)

    # --- Signature on sha256 hash of bytes of raw key response verifies.
    try:
        attestation_key.verify(attestation, key_raw, ec.ECDSA(SHA256()))
        print("Key attestation has been verified successfully")
    except:
        sys.exit(Fail.SGN_VERIFICATION.value)

    print(frame("==== Key refresh  ===="))
    # --- Refresh.
    refreshed = refresh_key(one_of(nodes), args.key)
    if type(refreshed) is Fail:
        sys.exit(refreshed.value)

    refreshed_pub_key = get_key(one_of(nodes), args.key)
    if type(refreshed_pub_key) is Fail:
        sys.exit(refreshed_pub_key.value)

    assert \
        pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo) == \
        refreshed_pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo), \
        "Generated and retrieved keys are different"

    # --- Sign.
    signature = sign(one_of(nodes), args.key, args.message)
    if type(signature) is Fail:
        sys.exit(signature.value)

    # --- Signature by new shards verifies with old public key.
    try:
        pub_key.verify(signature, args.message, ec.ECDSA(SHA256()))
        print("Signature has been verified successfully after the key refresh")
    except:
        sys.exit(Fail.SGN_VERIFICATION.value)


if __name__ == '__main__':
    sys.exit(main())
