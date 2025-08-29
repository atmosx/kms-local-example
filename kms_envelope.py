import argparse
import base64
import json
import os
import sys

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def kms_client():
    # Points boto3 to LocalStack instead of real AWS
    return boto3.client(
        "kms",
        region_name=os.getenv("AWS_REGION", "us-east-1"),
        endpoint_url=os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566"),
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
    )


def find_alias(client, alias_name):
    paginator = client.get_paginator("list_aliases")
    for page in paginator.paginate():
        for a in page.get("Aliases", []):
            if a.get("AliasName") == alias_name and a.get("TargetKeyId"):
                return a["TargetKeyId"]
    return None


def cmd_init(args):
    client = kms_client()
    alias_name = args.alias
    key_id = find_alias(client, alias_name)
    if key_id:
        print(f"Alias already exists: {alias_name} -> {key_id}")
        return

    resp = client.create_key(
        Description="LocalStack demo CMK for envelope encryption",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Origin="AWS_KMS",
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    client.create_alias(AliasName=alias_name, TargetKeyId=key_id)
    print(f"Created CMK: {key_id}")
    print(f"Created alias: {alias_name} -> {key_id}")


def generate_data_key(client, key_id):
    resp = client.generate_data_key(KeyId=key_id, KeySpec="AES_256")
    plaintext_key = resp["Plaintext"]          # bytes
    encrypted_key = resp["CiphertextBlob"]     # bytes (EDK)
    return plaintext_key, encrypted_key


def cmd_encrypt(args):
    client = kms_client()
    key_id = args.key_id or find_alias(client, args.alias)
    if not key_id:
        print("Error: no key found. Run 'init' first or pass --key-id.", file=sys.stderr)
        sys.exit(1)

    with open(args.input, "rb") as f:
        plaintext = f.read()

    data_key, edk = generate_data_key(client, key_id)
    try:
        aesgcm = AESGCM(data_key)
        nonce = os.urandom(12)  # AES-GCM recommended nonce size
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

        payload = {
            "key_id": key_id,
            "algorithm": "AES-256-GCM",
            "encrypted_data_key_b64": base64.b64encode(edk).decode("utf-8"),
            "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
        }
        with open(args.output, "w") as f:
            json.dump(payload, f)
        print(f"Encrypted to {args.output}")
    finally:
        # Best effort to reduce lifetime of plaintext key in memory
        del data_key


def cmd_decrypt(args):
    client = kms_client()
    with open(args.input, "r") as f:
        payload = json.load(f)

    edk = base64.b64decode(payload["encrypted_data_key_b64"])
    nonce = base64.b64decode(payload["nonce_b64"])
    ciphertext = base64.b64decode(payload["ciphertext_b64"])

    try:
        resp = client.decrypt(CiphertextBlob=edk)
        data_key = resp["Plaintext"]
        aesgcm = AESGCM(data_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        with open(args.output, "wb") as f:
            f.write(plaintext)
        print(f"Decrypted to {args.output}")
    finally:
        del edk  # minimize residuals
        try:
            del data_key
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Envelope encryption with LocalStack KMS")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Create a KMS CMK and alias in LocalStack")
    p_init.add_argument("--alias", default="alias/local/envelope-key", help="KMS alias to create/use")
    p_init.set_defaults(func=cmd_init)

    p_enc = sub.add_parser("encrypt", help="Encrypt a file using envelope encryption")
    p_enc.add_argument("-k", "--key-id", help="KMS KeyId to use (optional if alias exists)")
    p_enc.add_argument("--alias", default="alias/local/envelope-key", help="Alias to resolve if --key-id not provided")
    p_enc.add_argument("-i", "--input", required=True, help="Path to plaintext file")
    p_enc.add_argument("-o", "--output", required=True, help="Path to write JSON envelope ciphertext")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt a previously encrypted file")
    p_dec.add_argument("-i", "--input", required=True, help="Path to JSON envelope ciphertext")
    p_dec.add_argument("-o", "--output", required=True, help="Path to write decrypted plaintext")
    p_dec.set_defaults(func=cmd_decrypt)

    args = parser.parse_args()
    try:
        args.func(args)
    except ClientError as e:
        print(f"AWS/KMS error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

