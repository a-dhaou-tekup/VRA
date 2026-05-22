"""FastAPI authentication dependencies.

`require_role` is the canonical auth primitive for P1 RBAC.

The old `require_api_key` / `optional_api_key` helpers are kept as lightweight
shims so any code that still imports them continues to work without modification.
They are effectively no-ops once the JWT flow is in place — the routers that
have been migrated to `require_role` no longer call them.
"""

import os
from fastapi import Header, HTTPException, status

# Re-export the RBAC primitives so callers can do:
#   from api.dependencies import require_role
from api.auth import get_current_user, require_role  # noqa: F401

# ── Legacy shims (kept for backward compatibility) ────────────────────────────

_API_KEY = os.getenv("API_KEY", "change-me-in-prod")
_REQUIRE_AUTH_FOR_READS = os.getenv("REQUIRE_AUTH_FOR_READS", "false").lower() == "true"


def require_api_key(x_api_key: str = Header(default="")):
    """Legacy single-API-key guard — kept as a shim; new code uses require_role."""
    if x_api_key and x_api_key == _API_KEY:
        return x_api_key
    # If the caller passes a valid legacy key, accept it.
    # Otherwise this is a no-op (the router-level require_role already enforced auth).
    return x_api_key


def optional_api_key(x_api_key: str = Header(default="")):
    """Legacy optional guard — kept as a shim; new code uses require_role."""
    if _REQUIRE_AUTH_FOR_READS and x_api_key != _API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return x_api_key
