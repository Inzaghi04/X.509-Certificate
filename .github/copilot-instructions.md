# Repository guidance for AI coding agents ✅

This repository is a small OpenSSL X.509 / RSA demonstration and test suite implemented in plain C. The goal of the project is educational: show how to extract a public key from an X.509 certificate, encrypt with the public key, and decrypt with the corresponding private key. The tests exercise tampering, wrong-key, and size-limit behaviors.

---

## Quick start (build & run) 🔧
- Build the demo (requires OpenSSL development libs and pkg-config):

```bash
make            # uses pkg-config --cflags/--libs openssl (Makefile targets MSYS2 UCRT64)
./x509_demo     # (on Windows: x509_demo.exe)
```

- Build and run the tests (there's no tests target in the Makefile):

```bash
gcc tests.c -o run_tests $(pkg-config --cflags --libs openssl)
./run_tests
```

If `pkg-config` or OpenSSL dev packages are not present, set `CFLAGS`/`LDFLAGS` with explicit `-I`/`-L` and `-lssl -lcrypto`.

---

## Project structure & key files 📁
- `main.c` — demo program: loads `cert.pem`, extracts public key, performs `RSA_public_encrypt`, sends ciphertext, then reads `private.pem` and does `RSA_private_decrypt`.
- `tests.c` — small test harness: creates a temporary fake key for a wrong-key test, performs tampering and size-limit checks, and prints human-readable PASS/FAIL messages.
- `Makefile` — uses `pkg-config` to populate `OPENSSL_CFLAGS` and `OPENSSL_LIBS` (note comment: MSYS2 UCRT64).
- `cert.pem`, `private.pem` — example certificate and private key used by both programs.

---

## Important implementation patterns & examples 🔍
- X.509 / PEM usage
  - Read certificate: `PEM_read_X509(fp, NULL, NULL, NULL)` (see `main.c` / `tests.c`).
  - Extract public key: `EVP_PKEY *p = X509_get_pubkey(cert); RSA *r = EVP_PKEY_get1_RSA(p);` then use `RSA_public_encrypt`.
  - Read private key: `PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)` and use `RSA_private_decrypt`.

- Error-handling and debug aids
  - OpenSSL error helpers are used: `ERR_print_errors_fp(stderr)`, `ERR_get_error()` and `ERR_error_string()` — prefer these when investigating failures.

- Test expectations (useful for writing assertions)
  - Tampering test prints `>>> RESULT: PASS (System detected tampering and refused decryption)` on success.
  - Wrong-key test prints `>>> RESULT: PASS (Wrong key could not decrypt message)` on success.
  - Size limit test expects encryption failure (OpenSSL error printed) and prints `>>> RESULT: PASS (System prevented encrypting oversized data)`.
  - Failure modes are signaled through printed strings and non-zero exit codes (e.g. `CRITICAL ERROR: Cannot encrypt initial message. Check cert.pem!`).

---

## Security & behavioral notes (explicit in repo) ⚠️
- Certificate verification is intentionally omitted in the demo: `main.c` prints `"[Should verify certificate here - skipped in demo]"`. Do not assume CA validation is present.
- RSA padding is `RSA_PKCS1_PADDING` and encryption is limited by key size; `tests.c` demonstrates a size-limit test that intentionally fails for large inputs.
- Buffer sizes vary between `main.c` (uses a 256-byte decrypted buffer) and `tests.c` (uses a 2048-byte buffer). Be careful when changing buffers — tests rely on these sizes.

---

## Guidance for AI agents (concrete, actionable) 🤖
- When changing crypto code, preserve OpenSSL init/cleanup calls (`OpenSSL_add_all_algorithms`, `ERR_load_crypto_strings`, `EVP_cleanup`, `ERR_free_strings`).
- Use the same PEM API patterns above — small changes should keep `PEM_read_X509`/`X509_get_pubkey`/`PEM_read_RSAPrivateKey` call shapes to remain consistent with tests.
- If adding test coverage, assert on the exact `>>> RESULT:` strings printed in `tests.c` or on exit codes to keep CI checks simple and deterministic.
- When touching build flags, update the `Makefile` `OPENSSL_CFLAGS`/`OPENSSL_LIBS` usage rather than hard-coding include/lib paths to keep compatibility with MSYS2 / pkg-config setups.

---

## Where to look for examples in the codebase 🔎
- RSA/PEM usage: `main.c` and `tests.c` (search for `PEM_read_X509`, `X509_get_pubkey`, `RSA_public_encrypt`, `RSA_private_decrypt`).
- Test patterns and expected output strings: `tests.c` (search for `>>> RESULT:` and `CRITICAL ERROR`).

---

If you'd like, I can (1) add a `tests` target to the `Makefile` that builds & runs `tests.c`, and (2) add a simple CI job example for running the tests on GitHub Actions. Want me to add those? 💡
