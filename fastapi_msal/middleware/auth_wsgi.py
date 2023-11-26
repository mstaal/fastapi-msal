from typing import Any, Callable

from a2wsgi import WSGIMiddleware
from a2wsgi.types import Receive, Scope, Send
from fastapi_msal.middleware.exceptions import UnauthenticatedUser

# Reference: https://stackoverflow.com/questions/72390581/fastapi-auth-check-before-granting-access-to-sub-applications
# Reference: https://github.com/tiangolo/fastapi/issues/858#issuecomment-876564020


def authenticate(scope: Scope) -> None:
    if "user" in scope and scope["user"].is_authenticated:
        return
    raise UnauthenticatedUser(detail="Not authenticated", headers=scope["headers"])


class AuthWSGIMiddleware(WSGIMiddleware):
    def __init__(self, app: Callable[..., Any]) -> None:
        super().__init__(app)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        authenticate(scope)
        await super().__call__(scope, receive, send)
