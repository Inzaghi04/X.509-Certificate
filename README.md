# X.509 Certificate Demo (OpenSSL – C)

## 📌 Overview

This project is a **simple demonstration of using OpenSSL in C** to work with **X.509 certificates** and **RSA public/private keys**.

The program shows how to:
- Load an **X.509 certificate** from a PEM file
- Extract the **public key** from the certificate
- Perform **RSA encryption and decryption**
- Print binary data in **hexadecimal format** for debugging

This project is intended for **learning and experimentation**, not for production use.

---

## 📁 Project Structure

```text
X.509-Certificate-main/
├── main.c          # Main source code
├── MakeFile        # Build script
├── cert.pem        # X.509 certificate (contains public key)
├── private.pem     # RSA private key
├── x509_demo       # Compiled binary
└── README.md       # Project documentation
## ⚙️ Requirements
Linux / WSL / macOS

GCC compiler

OpenSSL development library (libssl-dev)

Install OpenSSL (Ubuntu / Debian)
bash
Copy code
sudo apt update
sudo apt install libssl-dev
Verify Installation
bash
Copy code
openssl version
## 🔨 Build Instructions
Using Makefile
bash
Copy code
make
After a successful build, the executable will be:

bash
Copy code
./x509_demo
Manual Build
bash
Copy code
gcc main.c -o x509_demo -lssl -lcrypto
##🚀 How to Run
bash
Copy code
./x509_demo
The program will:

Load the X.509 certificate (cert.pem)

Extract the RSA public key

Encrypt and decrypt sample data

Print results in hexadecimal format

##🔐 PEM File Explanation
cert.pem
Contains an X.509 certificate

Includes the public key

Typically used for:

Verifying digital signatures

Encrypting data for the private key owner

private.pem
Contains the RSA private key

Used for:

Decrypting data

Signing data

##⚠️ Never expose private keys in real-world projects

##🧠 OpenSSL APIs Used
Some important OpenSSL functions used in this project:

PEM_read_X509() – Read X.509 certificate from PEM file

X509_get_pubkey() – Extract public key from certificate

EVP_PKEY_get1_RSA() – Get RSA structure

RSA_public_encrypt() – Encrypt data using public key

RSA_private_decrypt() – Decrypt data using private key

OpenSSL error handling utilities

##🧪 Educational Purpose
This project is designed for:

Learning basic cryptography concepts

Understanding X.509 certificate handling

Practicing OpenSSL C APIs

Preparing for:

TLS / SSL

PKI systems

Secure communication
