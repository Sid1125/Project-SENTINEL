import secrets
from typing import Dict, Optional

from fastapi import Request
from fastapi.responses import JSONResponse

try:
    from models.database import settings
except ModuleNotFoundError:
    from backend.models.database import settings


AUTH_HEADER = "X-Sentinel-Token"
PUBLIC_PATHS = {
    "/",
    "/health",
    "/api/v1/auth/config",
    "/api/v1/auth/verify",
}
ROLE_PRIORITY = {
    "viewer": 1,
    "operator": 2,
    "admin": 3,
}


def is_auth_enabled() -> bool:
    return any(bool(token) for token in get_configured_roles().values())


def get_configured_roles() -> Dict[str, str]:
    roles = {
        "viewer": getattr(settings, "viewer_token", "") or "",
        "operator": getattr(settings, "operator_token", "") or "",
        "admin": getattr(settings, "admin_token", "") or "",
    }
    return {role: token for role, token in roles.items() if token}


def get_token_hint() -> str:
    configured_roles = get_configured_roles()
    strongest_token = configured_roles.get("admin") or configured_roles.get("operator") or configured_roles.get("viewer") or ""
    if not strongest_token:
        return "auth-disabled"
    if len(strongest_token) <= 4:
        return "*" * len(strongest_token)
    return f"{strongest_token[:2]}{'*' * (len(strongest_token) - 4)}{strongest_token[-2:]}"


def extract_token_from_request(request: Request) -> str:
    header_token = request.headers.get(AUTH_HEADER, "").strip()
    if header_token:
        return header_token

    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    return ""


def is_authorized_request(request: Request) -> bool:
    if not is_auth_enabled():
        return True

    if request.url.path in PUBLIC_PATHS:
        return True

    if not request.url.path.startswith("/api/v1"):
        return True

    return get_request_role(request) is not None


def get_request_role(request: Request) -> Optional[str]:
    provided_token = extract_token_from_request(request)
    if not provided_token:
        return None

    configured_roles = get_configured_roles()
    for role in ("admin", "operator", "viewer"):
        expected_token = configured_roles.get(role)
        if expected_token and secrets.compare_digest(provided_token, expected_token):
            return role
    return None


def has_minimum_role(request: Request, minimum_role: str) -> bool:
    if not is_auth_enabled():
        return True
    current_role = get_request_role(request)
    if not current_role:
        return False
    return ROLE_PRIORITY.get(current_role, 0) >= ROLE_PRIORITY.get(minimum_role, 0)


def unauthorized_response() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={
            "detail": "Operator authentication required",
            "auth_enabled": True,
            "header": AUTH_HEADER,
        },
    )


def forbidden_response(minimum_role: str, current_role: Optional[str]) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={
            "detail": f"{minimum_role.title()} role required",
            "required_role": minimum_role,
            "current_role": current_role,
            "auth_enabled": True,
        },
    )
