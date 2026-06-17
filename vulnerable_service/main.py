from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import jwt
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = FastAPI(title="JWT Vulnerable Service")

# --- Keys and secrets ---

# HS256 weak secret (used in attacks 1, 2, 3, 4)
WEAK_SECRET = "secret"

# RS256 key pair (used in attack 5)
# Generated once when the server starts, in memory only
_private_key_obj = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
PRIVATE_KEY = _private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
PUBLIC_KEY = _private_key_obj.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# --- Request model ---

class LoginRequest(BaseModel):
    username: str
    password: str

# --- Login route ---

@app.post("/login")
def login(data: LoginRequest):
    """
    Legitimate login endpoint.
    Returns a properly signed HS256 token.
    The exploits will use this token as a starting point.
    """
    if data.username != "user" or data.password != "password":
        raise HTTPException(status_code=401, detail="Invalid credentials")

    payload = {
        "sub": data.username,
        "role": "user",
        "exp": int(time.time()) + 60,  # expires in 60 seconds
    }
    token = jwt.encode(payload, WEAK_SECRET, algorithm="HS256")
    return {"token": token}

# --- Vulnerable endpoints ---

@app.get("/vuln/no-verify")
def vuln_no_verify(authorization: str = Header(...)):
    """
    Attack 1 - Missing signature verification.
    Decodes the token without verifying the signature.
    Anyone can modify the payload and the server will trust it.
    """
    token = authorization.removeprefix("Bearer ")
    try:
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["HS256"],
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=str(e))

    return {
        "message": f"Welcome, {payload.get('sub')}! Your role is: {payload.get('role')}",
        "payload": payload,
    }

@app.get("/vuln/alg-none")
def vuln_alg_none(authorization: str = Header(...)):
    """
    Attack 2 - alg=none.
    Accepts tokens regardless of the algorithm in the header,
    including none (no signature at all).
    """
    token = authorization.removeprefix("Bearer ")
    try:
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["HS256", "none"],
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=str(e))

    return {
        "message": f"Welcome, {payload.get('sub')}! Your role is: {payload.get('role')}",
        "payload": payload,
    }

@app.get("/vuln/no-expiry")
def vuln_no_expiry(authorization: str = Header(...)):
    """
    Attack 3 - No expiry validation.
    Verifies the signature correctly but never checks the exp claim.
    A token issued years ago is still valid.
    """
    token = authorization.removeprefix("Bearer ")
    try:
        payload = jwt.decode(
            token,
            WEAK_SECRET,
            algorithms=["HS256"],
            options={"verify_exp": False},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=str(e))

    return {
        "message": f"Welcome, {payload.get('sub')}! Your role is: {payload.get('role')}",
        "payload": payload,
    }

@app.get("/vuln/weak-secret")
def vuln_weak_secret(authorization: str = Header(...)):
    """
    Attack 4 - Weak secret.
    The server signs and verifies with WEAK_SECRET = "secret".
    An attacker who intercepts a valid token can crack the secret offline
    and then forge tokens with any payload.
    """
    token = authorization.removeprefix("Bearer ")
    try:
        payload = jwt.decode(
            token,
            WEAK_SECRET,
            algorithms=["HS256"]
            )
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=str(e))

    return {
        "message": f"Welcome, {payload.get('sub')}! Your role is: {payload.get('role')}",
        "payload": payload,
    }

@app.get("/vuln/alg-confusion")
def vuln_alg_confusion(authorization: str = Header(...)):
    """
    Attack 5 - Algorithm confusion (RS256 to HS256).
    The server expects RS256 but also accepts HS256.
    If an attacker signs a token with HS256 using the public key as the secret,
    the server will verify it successfully.
    """
    token = authorization.removeprefix("Bearer ")
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256", "HS256"],
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=str(e))

    return {
        "message": f"Welcome, {payload.get('sub')}! Your role is: {payload.get('role')}",
        "payload": payload,
    }

# --- Public key endpoint ---

@app.get("/public-key")
def get_public_key():
    """
    Exposes the RSA public key.
    Realistic - in production this would be a JWKS endpoint.
    The algorithm confusion exploit fetches this key to forge tokens.
    """
    return {"public_key": PUBLIC_KEY.decode()}