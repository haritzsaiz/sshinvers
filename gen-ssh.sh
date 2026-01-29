#!/bin/bash

# Configuration
CLIENT_CRT="client.crt"
CLIENT_KEY="client.key"
CA_SSH_KEY="client.key" # The SSH CA Private Key
ID="device-01"           # Common Name / Identity
SERIAL=$(date +%s)       # Example serial number

echo "--- Extracting x509 data ---"
# 1. Convert x509 PEM to DER (binary) and then to Base64
# This is what will be stored in the SSH extension
X509_BASE64=$(openssl x509 -in "$CLIENT_CRT" -outform DER | base64 | tr -d '\n')

echo "--- Preparing SSH Public Key ---"
# 2. Extract SSH Public Key from the x509/RSA Private Key
# This ensures the SSH cert and x509 cert share the same cryptographic identity
ssh-keygen -y -f "$CLIENT_KEY" > "$CLIENT_KEY.pub"

echo "--- Signing SSH Certificate ---"
# 3. Sign the key and embed the x509 Base64 as a custom extension
# Extension format: -O extension:name@domain=value
ssh-keygen -s "$CA_SSH_KEY" \
    -I "$ID" \
    -z "$SERIAL" \
    -O extension:x509-auth-data@yourdomain.com="$X509_BASE64" \
    -V +1h \
    "$CLIENT_KEY.pub"

echo "--- Success ---"
echo "Generated: ${CLIENT_KEY/.key/-cert.pub}"