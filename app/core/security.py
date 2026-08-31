from fastapi import Header, HTTPException
import jwt
from jwt import PyJWKClient
from .config import get_settings

_jwk_client = None


def _client():
    global _jwk_client

    if _jwk_client is None:
        settings = get_settings()
        _jwk_client = PyJWKClient(
            f"{settings.supabase_url}/auth/v1/.well-known/jwks.json"
        )

    return _jwk_client


async def require_user(
    authorization: str | None = Header(default=None),
) -> dict:

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header",
        )

    if not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authorization must use Bearer token",
        )

    token = authorization.split(" ", 1)[1].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing access token",
        )

    try:
        signing_key = _client().get_signing_key_from_jwt(token).key

        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["ES256", "RS256"],
            options={
                "verify_aud": False,
            },
        )

        return claims

    except Exception as exc:
        print(f"JWT verification failed: {exc}")

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired Supabase access token",
        )
