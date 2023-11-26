from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from msal import ConfidentialClientApplication
from starlette.status import HTTP_302_FOUND


def msal_auth_router(
    msal_client: ConfidentialClientApplication,
    scopes: list[str],
    prompt: Optional[str] = "select_account",
    home_path: str = "/",
    auth_root: str = "/auth",
    login_path: str = "/login",
    callback_path: str = "/callback",
):

    router = APIRouter(
        prefix=auth_root,
    )

    @router.get(login_path, response_class=RedirectResponse)
    async def login(request: Request, state: Optional[str] = None):
        redirect_url = state if state else home_path
        if request.user and request.user.is_authenticated:
            return RedirectResponse(url=redirect_url, status_code=HTTP_302_FOUND)

        callback_uri = request.url_for("callback")
        auth_url = msal_client.get_authorization_request_url(
            scopes=scopes, redirect_uri=callback_uri, state=state, prompt=prompt
        )
        return RedirectResponse(url=auth_url)

    @router.get(callback_path, response_class=RedirectResponse)
    async def callback(
        request: Request, state: Optional[str] = None, code: Optional[str] = None, session_state: Optional[str] = None
    ):
        redirect_url = state if state else home_path
        return RedirectResponse(url=redirect_url, status_code=HTTP_302_FOUND)

    return router
