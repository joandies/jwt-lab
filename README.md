# JWT Security Lab Toolkit

> **⚠️ DISCLAIMER — EDUCATIONAL USE ONLY**
> 
> This project is designed strictly for **educational and research purposes**.
> All attacks are demonstrated against a **locally running vulnerable service** built for this purpose.
> Do **not** use these techniques against any system you do not own or have explicit written permission to test.
> The author assumes no responsibility for misuse of this material.

---

## What is this?

A hands-on security toolkit that demonstrates the most common JWT (JSON Web Token) vulnerabilities - and how to defend against them.

The project has two components:

- **`vulnerable_service/`** - A FastAPI server with intentionally broken JWT authentication. Each endpoint has a specific flaw.
- **`exploits/`** - Python scripts that attack the vulnerable service, one vulnerability at a time.
- **`defenses/`** - The corrected versions of each vulnerable endpoint, with explanation.

Everything is local. No external services, no databases, no Docker required.

---

## Why JWTs matter

JWTs are the backbone of authentication in modern APIs and microservices. A misconfigured JWT validation can mean:

- Full authentication bypass (an attacker creates valid tokens without knowing any secret)
- Privilege escalation (modifying the payload to become an admin)
- Session persistence after logout (tokens that never truly expire)

These are not theoretical vulnerabilities, they appear regularly in real-world pentests and bug bounty reports.

---

## Prerequisites

- Python 3.10+
- A virtual environment (recommended)

```bash
git clone https://github.com/joandies/jwt-security-lab.git
cd jwt-security-lab
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Vulnerabilities covered

| # | Attack | Severity | Description |
|---|--------|----------|-------------|
| 1 | Missing signature verification | 🔴 Critical | Server decodes the token but never verifies the signature |
| 2 | `alg=none` attack | 🔴 Critical | Server accepts tokens with no signature if `alg` is set to `none` |
| 3 | No expiry validation | 🟠 High | Server never checks the `exp` claim — tokens are valid forever |
| 4 | Weak secret brute force | 🟠 High | HS256 secret is weak enough to crack offline |
| 5 | Algorithm confusion (RS256 → HS256) | 🔴 Critical | Server can be tricked into verifying an RS256 token using the public key as an HMAC secret |

---

## Attack 1 - Missing signature verification

### What's the flaw?

The server uses `jwt.decode()` but passes `options={"verify_signature": False}`. This means it reads the payload and trusts it completely, without checking whether the signature is valid or even present.

Anyone can take a JWT, modify the payload to change their username, role, or any other claim, and the server will accept it.

### Why does it work?

Decoding a JWT and verifying a JWT are two different operations. Decoding just reads the Base64-encoded payload. Verifying checks that the signature matches the payload using the secret or public key.

A common mistake is using a JWT library in "decode-only" mode, either by accident or to "simplify" development, and then forgetting to turn verification back on.

### How to run it

Terminal 1 - start the vulnerable server:
```bash
uvicorn vulnerable_service.main:app --reload
```

Terminal 2 - run the exploit:
```bash
python exploits/01_missing_verification.py
```

### Output

```
============================================================
ATTACK 1 - Missing signature verification
============================================================

[1] Logging in as 'user'...
    Token received: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c...

[2] Original payload: {'sub': 'user', 'role': 'user', 'exp': 1781708472}

[3] Forged payload:   {'sub': 'admin', 'role': 'admin', 'exp': 1781708472}

[4] Forged token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ...

[5] Sending forged token to /vuln/no-verify...

[6] Server response: {'message': 'Welcome, admin! Your role is: admin', 'payload': {'sub': 'admin', 'role': 'admin', 'exp': 1781708472}}

[!] ATTACK SUCCESSFUL - Server accepted a token with a fake signature
```

---

## Attack 2 - `alg=none`

### What's the flaw?

The JWT specification includes `none` as a valid algorithm value, meaning "this token is not signed". If the server does not explicitly reject tokens with `alg: none`, an attacker can forge a token with any payload they want and no signature at all.

### Why does it work?

The `alg` field lives in the JWT header, which is controlled by the client. If the server reads the algorithm from the token header instead of enforcing it server-side, the attacker can simply tell the server "trust me, no signature needed" by setting `alg: none`.

Most modern JWT libraries reject `none` by default, but older versions or misconfigured ones do not.

### How to run it

Terminal 1 - start the vulnerable server:
```bash
uvicorn vulnerable_service.main:app --reload
```

Terminal 2 - run the exploit:
```bash
python exploits/02_alg_none.py
```

### Output

```
============================================================
ATTACK 2 - alg=none
============================================================

[1] Logging in as 'user'...
    Token received: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c...

[2] Original payload: {'sub': 'user', 'role': 'user', 'exp': 1781708989}

[3] Forged payload:   {'sub': 'admin', 'role': 'admin', 'exp': 1781708989}

[4] Forged token (alg=none, no signature): eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG...
    Header:  {'alg': 'none', 'typ': 'JWT'}
    Note: token ends with a dot - the signature part is empty

[5] Sending forged token to /vuln/alg-none...

[6] Server response: {'message': 'Welcome, admin! Your role is: admin', 'payload': {'sub': 'admin', 'role': 'admin', 'exp': 1781708989}}

[!] ATTACK SUCCESSFUL - Server accepted a token with no signature
```

> **Note on the implementation:** In a real vulnerable server, the only flaw would be accepting `none` in the algorithms list - `algorithms=["HS256", "none"]`. Modern PyJWT rejects `alg=none` even when listed, so our vulnerable endpoint also sets `verify_signature: False` as a workaround to simulate the behavior of older or misconfigured libraries. The conceptual bug is the same: never accept `none` as a valid algorithm.

---

## Attack 3 - No expiry validation

### What's the flaw?

JWTs have an `exp` claim (expiration time). The server never checks it. A token issued today is equally valid in a year, or ten years. If a token is stolen, it is valid forever.

### Why does it work?

The `exp` claim is just a number in the payload. Nothing enforces it automatically - the server has to explicitly check it. If the developer forgets, or skips it during testing and never re-enables it, tokens never expire.

### How to run it

Terminal 1 - start the vulnerable server:
```bash
uvicorn vulnerable_service.main:app --reload
```

Terminal 2 - run the exploit:
```bash
python exploits/03_no_expiry.py
```

### Output

```
============================================================
ATTACK 3 - No expiry validation
============================================================

[1] Logging in via /login-no-expiry...
    Token received: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c...

[2] Token payload: {'sub': 'user', 'role': 'user'}
    Note: no 'exp' field - this token never expires

[3] Sending token to /vuln/no-expiry...

[4] Server response: {'message': 'Welcome, user! Your role is: user', 'payload': {'sub': 'user', 'role': 'user'}}

[!] ATTACK SUCCESSFUL - Server accepted a token with no expiry
    This token will remain valid forever - even if the user logs out
```

> **Variant B - expired token replay:** There is a second form of this vulnerability where the server does issue tokens with an `exp` claim, but never checks it during verification. In that case, an attacker who knows the signing secret (see Attack 4) can forge a token with an `exp` set in the past and the server will still accept it. These two attacks chain naturally: crack the secret with Attack 4, then forge an expired token with any payload and any expiry date.

---

## Attack 4 - Weak secret brute force

### What's the flaw?

The server signs tokens with HS256 using a weak secret (`secret`). HS256 is a symmetric algorithm - the same secret signs and verifies. If the secret is weak, an attacker who intercepts a valid token can crack it offline and then forge tokens signed with the same secret.

### Why does it work?

HS256 tokens can be verified by anyone who knows the secret. Cracking is done entirely offline - no requests to the server, no rate limiting, no detection. A weak secret falls in seconds with a wordlist attack.

### How to run it

Terminal 1 - start the vulnerable server:
```bash
uvicorn vulnerable_service.main:app --reload
```

Terminal 2 - run the exploit:
```bash
python exploits/04_weak_secret.py
```

### Output

*(Coming soon)*

---

## Attack 5 - Algorithm confusion (RS256 to HS256)

### What's the flaw?

The server is configured to use RS256 (asymmetric - private key signs, public key verifies). But it also accepts HS256 tokens. An attacker can take the server's public key (which is public by definition), use it as the HMAC secret, sign a forged token with HS256, and the server will verify it successfully - because it uses the public key to verify HS256 signatures too.

### Why does it work?

The server reads the `alg` field from the token header and switches verification mode accordingly. When it sees `HS256`, it uses the public key as the HMAC secret to verify. The attacker signed the token with that same public key. The verification passes.

This works because the server does not enforce which algorithm it expects - it lets the client decide.

### How to run it

Terminal 1 - start the vulnerable server:
```bash
uvicorn vulnerable_service.main:app --reload
```

Terminal 2 - run the exploit:
```bash
python exploits/05_alg_confusion.py
```

### Output

---

## Defense summary

*(Coming soon - a consolidated table of all fixes once all attacks are implemented)*

---

## Author

Joan Díes - Security Engineer  
[LinkedIn](https://linkedin.com/in/joan-dies) · [GitHub](https://github.com/joandies)