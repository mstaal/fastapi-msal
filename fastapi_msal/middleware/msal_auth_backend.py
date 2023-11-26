from datetime import datetime, timedelta
from typing import Optional, Tuple

from fastapi.requests import HTTPConnection
from msal import ConfidentialClientApplication
from starlette.authentication import AuthCredentials, AuthenticationBackend, AuthenticationError, BaseUser
from starlette.authentication import UnauthenticatedUser as StarletteUnauthenticatedUser


class UnauthenticatedUser(StarletteUnauthenticatedUser):
    @property
    def identity(self) -> str:
        return ""


class MSALUser(BaseUser):
    def __init__(self, token: dict) -> None:
        self.token = token
        self.expiration: datetime = datetime.utcnow() + timedelta(seconds=self.token["expires_in"])

    @property
    def id_token_claims(self) -> dict:
        return self.token["id_token_claims"]

    @property
    def is_authenticated(self) -> bool:
        if self.expiration > datetime.utcnow():
            return True
        return False

    @property
    def display_name(self) -> str:
        return self.id_token_claims["preferred_username"]

    @property
    def name(self) -> str:
        return self.id_token_claims["name"]

    @property
    def identity(self) -> str:
        return self.id_token_claims["oid"]


class MSALAuthBackend(AuthenticationBackend):
    """
    This is a custom auth backend class that will allow you to authenticate your request and return auth and user as
    a tuple
    """

    def __init__(self, msal_client: ConfidentialClientApplication, scopes: list[str]) -> None:
        self.msal_client: ConfidentialClientApplication = msal_client
        self.scopes: list[str] = scopes
        super().__init__()

    async def authenticate(self, request: HTTPConnection) -> Optional[Tuple[AuthCredentials, MSALUser]]:
        # We first go through the authentication process via Authorization Code Flow
        if "code" in request.query_params:
            token = self.msal_client.acquire_token_by_authorization_code(
                request.query_params["code"],
                scopes=self.scopes,
                redirect_uri=f"{request.url.scheme}://{request.url.netloc}{request.url.path}",
            )

            if "error" in token or "access_token" not in token:
                raise AuthenticationError("Authentication failed!")

            # Save the user in the session
            request.session["user"] = {
                "expires_in": token["expires_in"],
                "id_token_claims": token["id_token_claims"],
                "access_token": token["access_token"],
            }
            return AuthCredentials(["authenticated"]), MSALUser(request.session["user"])
        # If the user is already authenticated, we return the auth and user
        if "user" in request.session:
            preferred_username = request.session["user"].get("id_token_claims", dict()).get("preferred_username", None)
            accounts = self.msal_client.get_accounts(preferred_username)
            if not accounts:
                # User session is invalid
                del request.session["user"]
                return AuthCredentials(), UnauthenticatedUser()
            silent_token = self.msal_client.acquire_token_silent(self.scopes, account=accounts[0])
            if "error" in silent_token or "access_token" not in silent_token:
                return AuthCredentials(), UnauthenticatedUser()
            request.session["user"]["expires_in"] = silent_token["expires_in"]
            request.session["user"]["access_token"] = silent_token["access_token"]
            return AuthCredentials(["authenticated"]), MSALUser(request.session["user"])

        # If the user is not authenticated, we return an unauthenticated user with no roles
        return AuthCredentials(), UnauthenticatedUser()
