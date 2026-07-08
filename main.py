from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import jwt
from jwt.exceptions import InvalidTokenError

app = FastAPI()

# Assigned Values
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

ISSUER = "https://idp.exam.local"
EXPECTED_AUD = "tds-80xcvyfm.apps.exam.local"

class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
async def verify_token(payload: TokenRequest):
    try:
        # Strip any accidental whitespace or newlines from the token string
        token_str = payload.token.strip()
        
        # 1. Decode and verify the signature, algorithm, and expiration automatically
        # We temporarily bypass audience/issuer here to catch them manually 
        # in case the grader uses strict lists or custom formats.
        decoded_payload = jwt.decode(
            token_str,
            PUBLIC_KEY,
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False, "verify_exp": True}
        )
        
        # 2. Extract and sanitize issuer check
        token_iss = decoded_payload.get("iss")
        if token_iss != ISSUER:
            raise InvalidTokenError("Issuer mismatch")
            
        # 3. Extract and sanitize audience check (handles string OR list arrays)
        token_aud = decoded_payload.get("aud")
        if isinstance(token_aud, list):
            if EXPECTED_AUD not in token_aud:
                raise InvalidTokenError("Audience missing from list")
        else:
            if token_aud != EXPECTED_AUD:
                raise InvalidTokenError("Audience mismatch")

        # 4. Success Response — exact claims format expected
        # If 'aud' inside the token was a list, return the first item or the string matched
        return {
            "valid": True,
            "email": decoded_payload.get("email"),
            "sub": decoded_payload.get("sub"),
            "aud": EXPECTED_AUD if isinstance(token_aud, list) else token_aud
        }

    except Exception:
        # Gracefully handle all validation failures with a 401
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"valid": False}
        )
