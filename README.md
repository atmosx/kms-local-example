# Local KMS Envelope Encryption with LocalStack and Docker

This repository demonstrates how to run a local AWS KMS-compatible endpoint using LocalStack and how to perform envelope encryption in Python.
You’ll generate a data key with KMS, encrypt a file locally with AES-256-GCM, and store the encrypted data key alongside the ciphertext.

- LocalStack provides local KMS APIs so you can create and use symmetric keys for development and testing.
- It runs easily via Docker Compose.
- Services are exposed on the edge port 4566 by default.

## Prerequisites

- Docker and Docker Compose installed and running.
- Python 3.9+ and `pip`.
- Optional: AWS CLI for quick verification.

## Quick start

1. Start LocalStack (KMS only):

   ```bash
   docker compose up -d
   # configure endpoint
   aws --endpoint-url http://localhost:4566 --region us-east-1 kms list-keys
   # check if there are keys
   aws --no-cli-pager --endpoint-url http://localhost:4566 --region us-east-1 kms list-keys
   ```

2. Create and activate a virtual environment, then install dependencies:

   ```bash
   python -m venv .venv
   . .venv/bin/activate
   pip install -r requirements.txt
   ```

3. Initialize a local KMS key and alias:

   ```bash
   python kms_envelope.py init
   ```

4. Encrypt a file using envelope encryption:

   ```bash
   echo "Top secret text" > secret.txt
   python kms_envelope.py encrypt -i secret.txt -o secret.enc.json
   ```

5. Decrypt:
   ```bash
   python kms_envelope.py decrypt -i secret.enc.json -o secret.decrypted.txt
   diff -u secret.txt secret.decrypted.txt || true
   ```

## Working example

```bash
[atma:~/temp/kms-local]$ vim docker-compose.yaml
[atma:~/temp/kms-local]$ docker compose up -d
[+] Running 2/2
 ✔ Network kms-local_default         Created                                                                                                           0.0s
 ✔ Container kms-local-localstack-1  Started                                                                                                           0.2s

[atma:~/temp/kms-local]$ aws --endpoint-url http://localhost:4566 --region us-east-1 kms list-keys
[atma:~/temp/kms-local]$ aws --no-cli-pager --endpoint-url http://localhost:4566 --region us-east-1 kms list-keys
{
    "Keys": []
}

[atma:~/temp/kms-local]$ python kms_envelope.py init
    Created CMK: 95447e8f-1a42-4a8a-8070-d472587b4e3c
    Created alias: alias/local/envelope-key -> 95447e8f-1a42-4a8a-8070-d472587b4e3c

[atma:~/temp/kms-local]$ echo "oauth1-token" > secret.txt

# Encrypt using local KMS

[atma:~/temp/kms-local]$ python kms_envelope.py encrypt -i ./secret.txt -o ./secret.enc.json
Encrypted to ./secret.enc.json

[atma:~/temp/kms-local]$ cat secret.enc.json
{
  "key_id": "95447e8f-1a42-4a8a-8070-d472587b4e3c",
  "algorithm": "AES-256-GCM",
  "encrypted_data_key_b64": "OTU0NDdlOGYtMWE0Mi00YThhLTgwNzAtZDQ3MjU4N2I0ZTNjOIvf+vBRqGDdAbQn5u46EeWH3LLhv3YQf0EIifEvkqpv/NyXlChoVicmnOYNNIHk+GH3+UmGXRFnUMVG3tX09vyr2syU+0bTHqj+Uxe2yrI=",
  "nonce_b64": "QD7OaQPLFJ9PIfGJ",
  "ciphertext_b64": "QLo8b0K6fbQuAfv7oFRyyZUBcFwr6TEWJnMYFQI="
}

# Decrypt using local KMS
[atma:~/temp/kms-local]$ python kms_envelope.py decrypt -i ./secret.enc.json -o ./secret.decrypted.txt
Decrypted to ./secret.decrypted.txt

[atma:~/temp/kms-local]$ cat secret.decrypted.txt
oauth1-token
```

## How it works (envelope encryption)

- Request a data key from KMS.
- Use the plaintext data key locally to encrypt your data (AES-256-GCM).
- Store the encrypted data key (EDK) with your ciphertext.
- To decrypt, call KMS to unwrap the EDK and use the recovered plaintext key to decrypt your data.

This pattern keeps large data off KMS while protecting the data key with the KMS-managed key.

## Configuration

- LocalStack endpoint: `http://localhost:4566`
- Default region: `us-east-1`
- Default credentials used by the sample: `AWS_ACCESS_KEY_ID=test`, `AWS_SECRET_ACCESS_KEY=test`

You can override the endpoint or region for the Python client:

- `LOCALSTACK_ENDPOINT` (default: `http://localhost:4566`)
- `AWS_REGION` (default: `us-east-1`)

## Verifying KMS is running (optional)

If you have the AWS CLI installed:

```bash
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://localhost:4566 kms list-keys
```

## Repository structure

- `docker-compose.yml` — brings up LocalStack with KMS enabled.
- `kms_envelope.py` — Python sample using boto3 and cryptography for envelope encryption.
- `requirements.txt` — Python dependencies.
- `.gitignore` — ignores typical build artifacts and virtualenv.

## Troubleshooting

- If `init` fails with connection errors, ensure LocalStack is running:
  ```bash
  docker compose ps
  docker logs localstack -f
  ```
- If `encrypt` says no key found, run `init` first or pass `--key-id`.
- If AWS CLI commands fail, ensure you set test credentials and region:
  ```bash
  export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
  ```

## Cleanup

- Stop LocalStack:
  ```bash
  docker compose down
  ```
- Remove generated files:
  ```bash
  rm -f secret.txt secret.enc.json secret.decrypted.txt
  ```
