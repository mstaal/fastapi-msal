from typing import Any, Dict, Optional
from urllib.parse import urlencode

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse
from starlette.status import HTTP_302_FOUND


class UnauthenticatedUser(HTTPException):
    def __init__(self, detail: Any = None, headers: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(status_code=401, detail=detail, headers=headers)


async def requires_authenticated_login(request: Request, exc: UnauthenticatedUser):
    login_redirect = f"""{request.url_for("login")}?{urlencode({"state": str(request.url)})}"""
    return RedirectResponse(url=login_redirect, status_code=HTTP_302_FOUND)
