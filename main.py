import os

import uvicorn
from authlib.integrations.starlette_client import OAuth, OAuthError
from authlib.integrations.starlette_client.apps import RedirectResponse
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
    #  "GOOGLE_REDIRECT_URI": GOOGLE_REDIRECT_URI,
}
starlette_config = Config(".env")
oauth = OAuth(starlette_config)
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# Session Middleware
SECRET_KEY = os.environ.get("SECRET_KEY") or None
if SECRET_KEY is None:
    raise BaseException("Missing SECRET_KEY")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)


@app.get("/")
async def public(request: Request) -> HTMLResponse:
    user = request.session.get("user")
    if user:
        name = user.get("name")
        return HTMLResponse(f"<p>Hello {name}!</p><a href=/logout>Logout</a>")
    return HTMLResponse("<a href=/login>Login</a>")


@app.route("/login")
async def login(request: Request) -> Response:
    redirect_uri = GOOGLE_REDIRECT_URI
    return await oauth.google.authorize_redirect(request, redirect_uri)  # type: ignore


@app.route("/auth")
async def auth(request: Request) -> None | RedirectResponse:
    print("request :=>", request)
    try:
        token = await oauth.google.authorize_access_token(request)  # type:ignore
        user = token.get("userinfo")
        if user:
            request.session["user"] = user
        return RedirectResponse(url="/")
    except OAuthError as e:
        print("OAuthError :=>", e)
        return RedirectResponse(url="/")


@app.route("/logout")
async def logout(request: Request) -> RedirectResponse:
    request.session.pop("user", None)
    return RedirectResponse(url="/")


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
