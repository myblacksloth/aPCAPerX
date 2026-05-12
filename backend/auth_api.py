"""
FastAPI helpers and routes for password, TOTP, recovery-code, and passkey auth.
"""

import base64
import inspect
import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from config import (
    AUTH_ENABLED,
    SESSION_COOKIE_NAME,
    WEBAUTHN_ORIGIN,
    WEBAUTHN_RP_ID,
    WEBAUTHN_RP_NAME,
)
from models import (
    LoginRequest,
    PasskeyLoginOptionsRequest,
    PasskeyVerifyRequest,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    UserProfile,
)
from auth_store import (
    add_passkey,
    create_session,
    delete_session,
    disable_totp,
    enable_totp,
    get_passkey_by_credential,
    get_user_by_id,
    get_user_by_session,
    get_user_by_username,
    init_auth_db,
    list_user_passkeys,
    pop_latest_challenge,
    save_challenge,
    start_totp_setup,
    update_passkey_usage,
    user_profile,
    verify_password,
    verify_recovery_code,
    verify_totp,
)

try:
    from webauthn import (
        generate_authentication_options,
        generate_registration_options,
        options_to_json,
        verify_authentication_response,
        verify_registration_response,
    )
    from webauthn.helpers.structs import (
        AuthenticationCredential,
        PublicKeyCredentialDescriptor,
        RegistrationCredential,
        UserVerificationRequirement,
    )
except Exception:  # pragma: no cover - dependency is installed in Docker.
    generate_authentication_options = None
    generate_registration_options = None
    options_to_json = None
    verify_authentication_response = None
    verify_registration_response = None
    AuthenticationCredential = None
    PublicKeyCredentialDescriptor = None
    RegistrationCredential = None
    UserVerificationRequirement = None


router = APIRouter(prefix="/api/auth", tags=["Auth"])


def _b64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url for JSON storage."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    """Decode unpadded base64url strings from WebAuthn storage."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _set_session_cookie(response: Response, token: str) -> None:
    """Set the HTTP-only session cookie."""
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )


def _credential_id_from_payload(payload: Dict[str, Any]) -> str:
    """Read the WebAuthn credential id from a browser payload."""
    return str(payload.get("id") or payload.get("rawId") or "")


def _parse_webauthn_model(model_class, payload: Dict[str, Any]):
    """Parse WebAuthn pydantic models across pydantic v1/v2 APIs."""
    if hasattr(model_class, "model_validate"):
        return model_class.model_validate(payload)
    return model_class.parse_obj(payload)


def _call_with_supported_kwargs(func, **kwargs):
    """Call third-party WebAuthn helpers across minor API differences."""
    supported = set(inspect.signature(func).parameters)
    return func(**{key: value for key, value in kwargs.items() if key in supported})


def require_user(request: Request) -> Dict[str, Any]:
    """Resolve the current authenticated user or reject the request."""
    if not AUTH_ENABLED:
        return {"id": "00000000-0000-0000-0000-000000000000", "username": "disabled", "display_name": "Auth disabled"}
    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    user = get_user_by_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


@router.on_event("startup")
def startup_auth() -> None:
    """Initialize the user database on backend startup."""
    if AUTH_ENABLED:
        init_auth_db()


@router.post("/login", response_model=UserProfile)
def login(payload: LoginRequest, response: Response):
    """Authenticate with username/password plus optional MFA or recovery code."""
    user = get_user_by_username(payload.username)
    if not user or not verify_password(user, payload.password):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    if user.get("totp_enabled"):
        valid_totp = payload.mfa_code and verify_totp(user["totp_secret"], payload.mfa_code)
        valid_recovery = payload.recovery_code and verify_recovery_code(str(user["id"]), payload.recovery_code)
        if not valid_totp and not valid_recovery:
            raise HTTPException(status_code=401, detail="MFA code or recovery code required.")

    _set_session_cookie(response, create_session(str(user["id"])))
    return user_profile(user)


@router.post("/logout")
def logout(request: Request, response: Response):
    """Clear the current session."""
    delete_session(request.cookies.get(SESSION_COOKIE_NAME, ""))
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"status": "ok"}


@router.get("/me", response_model=UserProfile)
def me(user: Dict[str, Any] = Depends(require_user)):
    """Return the current user profile."""
    return user_profile(user)


@router.post("/totp/setup", response_model=TOTPSetupResponse)
def totp_setup(user: Dict[str, Any] = Depends(require_user)):
    """Start TOTP enrollment and return the authenticator URI."""
    secret = start_totp_setup(str(user["id"]))
    label = f"{WEBAUTHN_RP_NAME}:{user['username']}"
    otpauth = f"otpauth://totp/{label}?secret={secret}&issuer={WEBAUTHN_RP_NAME}&algorithm=SHA1&digits=6&period=30"
    return TOTPSetupResponse(secret=secret, otpauth_url=otpauth)


@router.post("/totp/enable", response_model=UserProfile)
def totp_enable(payload: TOTPVerifyRequest, user: Dict[str, Any] = Depends(require_user)):
    """Enable TOTP after validating a code."""
    if not enable_totp(str(user["id"]), payload.code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code.")
    refreshed = get_user_by_session("") or user
    refreshed = {**user, "totp_enabled": True}
    return user_profile(refreshed)


@router.post("/totp/disable", response_model=UserProfile)
def totp_disable(user: Dict[str, Any] = Depends(require_user)):
    """Disable TOTP for the current user."""
    disable_totp(str(user["id"]))
    return user_profile({**user, "totp_enabled": False, "totp_secret": None})


@router.post("/passkeys/register/options")
def passkey_register_options(user: Dict[str, Any] = Depends(require_user)):
    """Generate WebAuthn registration options for the current user."""
    if generate_registration_options is None:
        raise HTTPException(status_code=503, detail="Passkey support is not installed.")
    existing = [
        PublicKeyCredentialDescriptor(id=_b64url_decode(item["credential_id"]))
        for item in list_user_passkeys(str(user["id"]))
    ]
    options = _call_with_supported_kwargs(
        generate_registration_options,
        rp_id=WEBAUTHN_RP_ID,
        rp_name=WEBAUTHN_RP_NAME,
        user_id=str(user["id"]).encode("utf-8"),
        user_name=user["username"],
        user_display_name=user["display_name"],
        exclude_credentials=existing,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    save_challenge(_b64url(options.challenge), "registration", user_id=str(user["id"]))
    return json.loads(options_to_json(options))


@router.post("/passkeys/register/verify", response_model=UserProfile)
def passkey_register_verify(payload: PasskeyVerifyRequest, user: Dict[str, Any] = Depends(require_user)):
    """Verify and store a new passkey credential."""
    if verify_registration_response is None:
        raise HTTPException(status_code=503, detail="Passkey support is not installed.")
    credential = _parse_webauthn_model(RegistrationCredential, payload.credential)
    challenge = pop_latest_challenge("registration", user_id=str(user["id"]))
    if not challenge:
        raise HTTPException(status_code=400, detail="Passkey challenge expired.")
    verified = _call_with_supported_kwargs(
        verify_registration_response,
        credential=credential,
        expected_challenge=_b64url_decode(challenge["challenge"]),
        expected_origin=WEBAUTHN_ORIGIN,
        expected_rp_id=WEBAUTHN_RP_ID,
    )
    add_passkey(
        str(user["id"]),
        _b64url(verified.credential_id),
        _b64url(verified.credential_public_key),
        verified.sign_count,
        payload.label or "Default passkey",
    )
    return user_profile(user)


@router.post("/passkeys/login/options")
def passkey_login_options(payload: PasskeyLoginOptionsRequest):
    """Generate WebAuthn authentication options for one username."""
    if generate_authentication_options is None:
        raise HTTPException(status_code=503, detail="Passkey support is not installed.")
    user = get_user_by_username(payload.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    allow_credentials = [
        PublicKeyCredentialDescriptor(id=_b64url_decode(item["credential_id"]))
        for item in list_user_passkeys(str(user["id"]))
    ]
    options = _call_with_supported_kwargs(
        generate_authentication_options,
        rp_id=WEBAUTHN_RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    save_challenge(_b64url(options.challenge), "authentication", user_id=str(user["id"]), username=user["username"])
    return json.loads(options_to_json(options))


@router.post("/passkeys/login/verify", response_model=UserProfile)
def passkey_login_verify(payload: PasskeyVerifyRequest, response: Response):
    """Verify a passkey assertion and create a session."""
    if verify_authentication_response is None:
        raise HTTPException(status_code=503, detail="Passkey support is not installed.")
    credential_id = _credential_id_from_payload(payload.credential)
    passkey = get_passkey_by_credential(credential_id)
    if not passkey:
        raise HTTPException(status_code=401, detail="Unknown passkey.")
    credential = _parse_webauthn_model(AuthenticationCredential, payload.credential)
    user = get_user_by_id(str(passkey["user_id"]))
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")
    challenge = pop_latest_challenge("authentication", user_id=str(user["id"]))
    if not challenge:
        raise HTTPException(status_code=400, detail="Passkey challenge expired.")
    verified = _call_with_supported_kwargs(
        verify_authentication_response,
        credential=credential,
        expected_challenge=_b64url_decode(challenge["challenge"]),
        expected_origin=WEBAUTHN_ORIGIN,
        expected_rp_id=WEBAUTHN_RP_ID,
        credential_public_key=_b64url_decode(passkey["public_key"]),
        credential_current_sign_count=passkey["sign_count"],
    )
    update_passkey_usage(passkey["credential_id"], verified.new_sign_count)
    _set_session_cookie(response, create_session(str(user["id"])))
    return user_profile(user)
