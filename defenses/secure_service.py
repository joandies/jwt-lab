from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import jwt
import time
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = FastAPI(title="JWT Secure Service")

# --- Keys and secrets ---

# Strong secret - generated randomly at startup, never hardcoded.
# In production: load from a secrets manager (AWS Secrets Manager,
# HashiCorp Vault, etc.) and rotate periodically.
STRONG_SECRET = secrets.token_hex(32)  # 32 bytes = 256 bits, well above HS256 minimum

# RS256 key pair - only used in the /secure/protected endpoint
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

# --- Secure login ---

@app.post("/secure/login")
def secure_login(data: LoginRequest):
    """
    Secure login endpoint.
    - Strong randomly generated secret, never hardcoded
    - Always includes exp (15 minutes) and iat claims
    """
    if data.username != "user" or data.password != "password":
        raise HTTPException(status_code=401, detail="Invalid credentials")

    payload = {
        "sub": data.username,
        "role": "user",
        "iat": int(time.time()),         # issued at
        "exp": int(time.time()) + 900,   # expires in 15 minutes
    }
    token = jwt.encode(payload, STRONG_SECRET, algorithm="HS256")
    return {"token": token}

# --- Single secure protected endpoint ---

@app.get("/secure/protected")
def secure_protected(authorization: str = Header(...)):
    """
    The correct JWT validation pattern - all five defenses applied:

    1. Full signature verification - no verify_signature: False
    2. Explicit algorithm whitelist - only HS256, never 'none'
    3. Expiry validation - verify_exp is True by default, never disabled
    4. Strong secret - randomly generated, never hardcoded
    5. Single algorithm enforced - the server decides, not the token header
    """
    token = authorization.removeprefix("Bearer ")
    try:
        payload = jwt.decode(
            token,
            STRONG_SECRET,       # defense 4 - strong secret, not hardcoded
            algorithms=["HS256"] # defense 2 and 5 - explicit whitelist, single algorithm
            # defense 1 - no options override, full verification by default
            # defense 3 - no verify_exp override, expiry checked by default
        )
    except jwt.ExpiredSignatureError:
        # defense 3 - explicit handling of expired tokens
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidAlgorithmError:
        # defense 2 and 5 - token used an algorithm not in the whitelist
        raise HTTPException(status_code=401, detail="Invalid algorithm")
    except jwt.InvalidSignatureError:
        # defense 1 - signature did not match
        raise HTTPException(status_code=401, detail="Invalid signature")
    except jwt.InvalidTokenError as e:
        # catch-all for any other JWT validation error
        raise HTTPException(status_code=401, detail=str(e))

    return {
        "message": f"Welcome, {payload.get('sub')}! Your role is: {payload.get('role')}",
        "payload": payload,
    }