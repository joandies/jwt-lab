# JWT Security Lab Toolkit

> **⚠️ DISCLAIMER — EDUCATIONAL USE ONLY**
> 
> This project is designed strictly for **educational and research purposes**.
> All attacks are demonstrated against a **locally running vulnerable service** built for this purpose.
> Do **not** use these techniques against any system you do not own or have explicit written permission to test.
> The author assumes no responsibility for misuse of this material.

---

## Contents

- [What is this?](#what-is-this)
- [Why JWTs matter](#why-jwts-matter)
- [Prerequisites](#prerequisites)
- [Vulnerabilities covered](#vulnerabilities-covered)
- [Attack 1 — Missing signature verification](#attack-1---missing-signature-verification)
- [Attack 2 — `alg=none`](#attack-2---algnone)
- [Attack 3 — No expiry validation](#attack-3---no-expiry-validation)
- [Attack 4 — Weak secret brute force](#attack-4---weak-secret-brute-force)
- [Attack 5 — Algorithm confusion (RS256 to HS256)](#attack-5---algorithm-confusion-rs256-to-hs256)
- [Demo](#demo)
- [Defense summary](#defense-summary)
- [The five golden rules](#the-five-golden-rules)
- [Roadmap](#roadmap)
- [Author](#author)

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
git clone https://github.com/joandies/jwt-lab.git
cd jwt-lab
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

```
============================================================
ATTACK 4 - Weak secret brute force
============================================================

[1] Logging in as 'user'...
    Token received: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c...

[2] Original payload: {'sub': 'user', 'role': 'user', 'exp': 1781716955}

[3] Brute forcing secret with 10 candidates...
    (warnings below are PyJWT flagging weak key candidates - expected)
InsecureKeyLengthWarning: The HMAC key is 8 bytes long...
InsecureKeyLengthWarning: The HMAC key is 6 bytes long...
InsecureKeyLengthWarning: The HMAC key is 5 bytes long...
InsecureKeyLengthWarning: The HMAC key is 7 bytes long...
    [!] Secret cracked: 'secret'

[4] Forged payload: {'sub': 'admin', 'role': 'admin', 'exp': 1781716955}
    Forged token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ...

[5] Sending forged token to /vuln/weak-secret...

[6] Server response: {'message': 'Welcome, admin! Your role is: admin', 'payload': {'sub': 'admin', 'role': 'admin', 'exp': 1781716955}}

[!] ATTACK SUCCESSFUL - Secret cracked and token forged
    The signing secret 'secret' was found in a wordlist
    An attacker can now forge any token with any payload
```

> **Note on wordlists:** This exploit uses a small hardcoded wordlist of 10 common secrets for demonstration purposes. In a real attack, tools like [hashcat](https://hashcat.net/hashcat/) with large wordlists such as `rockyou.txt` (14 million passwords) would be used instead. The mechanism is identical - the difference is scale. A weak secret falls in seconds regardless of wordlist size.

> **Connection to Attack 3:** Once the secret is cracked, an attacker can also forge tokens with an `exp` claim set in the past. If the server does not validate expiry (Attack 3, Variant B), a cracked secret enables full control over any token claim - including expiration.

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

```
============================================================
ATTACK 5 - Algorithm confusion (RS256 to HS256)
============================================================

[1] Fetching public key from /public-key...
    Public key retrieved (451 bytes)
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBC...

[2] Forged payload: {'sub': 'admin', 'role': 'admin'}

[3] Signing forged token with HS256 using the public key as HMAC secret...
    (building token manually - JWT libraries block this by design)
    Forged token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ...

[4] Sending forged token to /vuln/alg-confusion...

[5] Server response: {'message': 'Welcome, admin! Your role is: admin', 'payload': {'sub': 'admin', 'role': 'admin'}}

[!] ATTACK SUCCESSFUL - Server verified an HS256 token signed with its own public key
    The public key is public by definition - no secret was stolen
    The attacker only needed the public endpoint /public-key
```

> **Note on modern library protections and lab workarounds:**
>
> This attack exposes an interesting tension between realism and modern library safety features.
>
> **On the exploit side:** Both PyJWT and python-jose detect when a PEM-formatted RSA key is passed as an HMAC secret and block the operation with `InvalidKeyError`. This is a deliberate protection against exactly this attack. In a real scenario, an attacker would use a lower-level tool or build the token manually - which is exactly what `05_alg_confusion.py` does, using Python's standard `hmac` and `hashlib` modules directly, bypassing all library-level checks.
>
> **On the server side:** The same protection fires when the server tries to verify the forged token. PyJWT refuses to use the RSA public key as an HMAC secret during verification. To simulate the behavior of a vulnerable server (one running an older library version or a different language/framework without this protection), the lab's `vuln_alg_confusion` endpoint uses `verify_signature: False` as a workaround - similar to what was done in Attack 2.
>
> **The conceptual vulnerability is real.** In older versions of PyJWT (before 2.4.0), node's `jsonwebtoken`, and other JWT libraries, this attack worked end-to-end without any workarounds. The fix was precisely to add the RSA key detection that blocks this. The lab demonstrates the mechanism accurately - only the enforcement layer differs from a pre-fix environment.

## Are these vulnerabilities realistic?

A fair question. No competent developer intentionally puts `verify_signature: False` in production or adds `"none"` to their algorithm list. So why does this lab exist?

Because in practice, these vulnerabilities appear in three ways:

**Legacy code and older library versions.**
Before PyJWT 2.x, the default behavior was far more permissive. `alg=none` was accepted without any special configuration. Other languages and frameworks have similar histories - Node's `jsonwebtoken`, PHP libraries, Java's `jjwt` - each has had versions where these behaviors were either the default or easy to accidentally enable. There are production systems running today on library versions that predate these protections.

**The development shortcut that reaches production.**
This is the most common real-world case. A developer disables signature verification locally to avoid generating valid tokens during testing. The change gets committed, passes code review because nobody searches for that specific option, and reaches production. Bug bounty reports are full of exactly this pattern.

**Misconfiguration under complexity.**
In large codebases with multiple teams, JWT validation logic gets abstracted, wrapped, and reused. A `verify_exp: False` added for a specific internal service ends up in a shared middleware used everywhere. Nobody notices because the tests pass, they just never tested with an expired token.

**Attack 5 (algorithm confusion) is the exception.**
This one is not obvious at all and appears in well-maintained systems. Accepting both RS256 and HS256 can seem reasonable - "we support both for flexibility" - without the developer realizing it opens this attack vector. This vulnerability has appeared in real-world penetration tests and CVEs against production systems.

The goal of this lab is not to say "developers are careless". It is to build the habit of understanding why each validation option exists, so you never disable one without knowing exactly what you are giving up.

---
## Demo

Watch the algorithm confusion attack (RS256 → HS256) in action: the most technically sophisticated vulnerability in this lab.

[![asciicast](https://asciinema.org/a/cEdGlEfU4QFgR6uR.svg)](https://asciinema.org/a/cEdGlEfU4QFgR6uR)

The demo runs the same attack documented in [Attack 5](#attack-5---algorithm-confusion-rs256-to-hs256), with narrated steps and slower pacing for clarity.

## Defense summary

All five defenses are applied together in [`defenses/secure_service.py`](defenses/secure_service.py) as a single correct JWT validation pattern. Security is not about fixing one thing, it's about applying all the rules at once.

| # | Attack | Root cause | Fix |
|---|--------|------------|-----|
| 1 | Missing signature verification | `verify_signature: False` in decode call | Remove the option entirely - PyJWT verifies by default |
| 2 | `alg=none` | Server accepts `none` as a valid algorithm | Whitelist only the algorithm you use, never include `none` |
| 3 | No expiry validation | `verify_exp: False` or missing `exp` claim | Always include `exp` when issuing tokens, never disable `verify_exp` |
| 4 | Weak secret brute force | Hardcoded weak secret (`"secret"`) | Use `secrets.token_hex(32)` - never hardcode secrets in source code |
| 5 | Algorithm confusion | Server accepts both RS256 and HS256 | Enforce a single algorithm server-side - the server decides, not the token |

### The correct validation pattern

```python
payload = jwt.decode(
    token,
    STRONG_SECRET,        # defense 4 - strong secret, never hardcoded
    algorithms=["HS256"]  # defenses 2 and 5 - explicit whitelist, single algorithm
    # defense 1 - no verify_signature override, full verification by default
    # defense 3 - no verify_exp override, expiry checked by default
)
```

### The five golden rules

**1. The server decides the algorithm, not the token.**
Never read the `alg` field from the token header to decide how to verify it. Hardcode the expected algorithm on the server side. If you expect HS256, only accept HS256.

**2. Always verify the signature.**
Decoding and verifying are different operations. A decoded token tells you nothing without signature verification. Never use `verify_signature: False` outside of debugging.

**3. Always validate `exp`.**
Tokens without expiry are sessions that never end. Always include `exp` when issuing tokens. Short expiry windows (15-30 minutes) limit the damage of a stolen token significantly.

**4. Never hardcode secrets.**
Use `secrets.token_hex(32)` or equivalent at minimum. In production, load secrets from environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault). Rotate secrets periodically.

**5. Use asymmetric keys (RS256) for distributed systems.**
If multiple services need to verify tokens, RS256 lets you share the public key without exposing the signing secret. But enforce RS256 exclusively - never allow HS256 as a fallback, as that opens the door to algorithm confusion.

---

## Roadmap

Planned for future iterations:

- **JWT `kid` header injection** — manipulating the `kid` header to point the verifier to an attacker-controlled key.
- **JWKS confusion** — abusing dynamic JWKS endpoints to inject malicious keys.
- **Token replay protection** — demonstrating attacks against systems without `jti` or nonce tracking.
- **Refresh token vulnerabilities** — common flaws in refresh token rotation.

Contributions and suggestions welcome via issues.

---
## Author

Joan Díes - Security Engineer  
[LinkedIn](https://linkedin.com/in/joan-dies) · [GitHub](https://github.com/joandies)