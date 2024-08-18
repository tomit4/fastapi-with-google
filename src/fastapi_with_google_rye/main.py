import os
from typing import Any

import httpx
import uvicorn  # type:ignore
from authlib.integrations.starlette_client import OAuth  # type:ignore
from authlib.integrations.starlette_client import OAuthError  # type:ignore
from authlib.integrations.starlette_client.apps import RedirectResponse  # type:ignore
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse

app = FastAPI()
load_dotenv()
HOST = os.environ.get("HOST") or "127.0.0.1"
PORT = int(str(os.environ.get("PORT"))) or 5173

# OAuth settings
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID") or None
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET") or None
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI") or None
if (
    GOOGLE_CLIENT_ID is None
    or GOOGLE_CLIENT_SECRET is None
    or GOOGLE_REDIRECT_URI is None
):
    raise BaseException("Missing env variables")

# Oauth Config
config_data = {
    "GOOGLE_CLIENT_ID": GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": GOOGLE_CLIENT_SECRET,
    "GOOGLE_REDIRECT_URI": GOOGLE_REDIRECT_URI,
}
starlette_config = Config(".env")
oauth = OAuth(starlette_config)
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile",
        "prompt": "consent",
    },
)

# Session Middleware
SECRET_KEY = os.environ.get("SECRET_KEY") or None
if SECRET_KEY is None:
    raise BaseException("Missing SECRET_KEY")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)


# Helper functions for use with google oauth api
async def get_user_info(access_token: str) -> dict[str, Any] | None:
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://www.googleapis.com/oauth2/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response.status_code == 200:
            return response.json()
        return None


async def refresh_access_token(refresh_token: str) -> dict[str, Any] | None:
    token_url = "https://oauth2.googleapis.com/token"
    payload = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    async with httpx.AsyncClient() as client:
        token_response = await client.post(token_url, data=payload)
        if token_response.status_code == 200:
            return token_response.json()
    return None


# Simple helper function that sets the access token and refresh token as secure cookies
def set_cookie_tokens(response: Response, access_token, refresh_token=None) -> Response:
    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        secure=True,
    )
    if refresh_token:
        response.set_cookie(
            "refresh_token",
            refresh_token,
            httponly=True,
            secure=True,
        )
    return response


# TODO: Needs a refactor, already too long of a function
@app.get("/")
async def public(request: Request) -> Response:
    user = request.session.get("user")
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")

    if access_token:
        user = await get_user_info(access_token)
        if user:
            request.session["user"] = user
    elif user is None and refresh_token:
        new_token = await refresh_access_token(refresh_token)
        if new_token:
            new_access_token = new_token.get("access_token")
            if new_access_token:
                response = RedirectResponse(url="/")
                response = set_cookie_tokens(response, new_access_token)
                return response
    if user:
        name = user.get("name")
        return HTMLResponse(f"<p>Hello {name}!</p><a href=/logout>Logout</a>")
    return HTMLResponse("<a href=/login>Login</a>")


@app.route("/login")
async def login(request: Request) -> Response:
    redirect_uri = GOOGLE_REDIRECT_URI
    # NOTE: access_type="offline" gives you access to the refresh token
    return await oauth.google.authorize_redirect(request, redirect_uri, access_type="offline")  # type: ignore


@app.route("/auth")
async def auth(request: Request) -> Response:
    try:
        token = await oauth.google.authorize_access_token(request)  # type:ignore
        access_token = token.get("access_token")
        refresh_token = token.get("refresh_token")
        response = RedirectResponse(url="/")
        response = set_cookie_tokens(response, access_token, refresh_token)
        return response
    except OAuthError as e:
        print("OAuthError :=>", e)
        return RedirectResponse(url="/")


@app.route("/logout")
async def logout(request: Request) -> RedirectResponse:
    request.session.pop("user", None)

    response = RedirectResponse(url="/")
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return response


def main():
    uvicorn.run(app, host=HOST, port=PORT)
