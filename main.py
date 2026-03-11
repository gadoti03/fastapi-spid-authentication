from fastapi import FastAPI

from spid.handlers import (
    spid_config_error_handler,
    spid_signature_error_handler,
    spid_validation_error_handler,
    spid_internal_error_handler,
    session_error_handler,
)
from spid.exceptions import (
    SpidConfigError,
    SpidSignatureError,
    SpidValidationError,
    SpidInternalError,
    SessionError,
)

from database.connection import engine, Base

from routers.login import router as login_router
from routers.spid import router as spid_router

from fastapi.middleware.cors import CORSMiddleware

from schemas.models import HealthResponse

from fastapi import APIRouter
from fastapi.responses import Response, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request

import logging
    
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# cors settings
#   allow all origins to access the API (with fetch API from browser)
#   set header Access-Control-Allow-Origin: <origin>
#   is a protection browser-side (it act on the client's browser)
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# create all tables
Base.metadata.create_all(bind=engine)

# exception handlers
app.add_exception_handler(SpidConfigError, spid_config_error_handler)
app.add_exception_handler(SpidSignatureError, spid_signature_error_handler)
app.add_exception_handler(SpidValidationError, spid_validation_error_handler)
app.add_exception_handler(SpidInternalError, spid_internal_error_handler)
app.add_exception_handler(SessionError, session_error_handler)

# root route
@app.get("/", response_class=HTMLResponse)
async def health():
    try:
        with open("session.txt", "r") as f:
            session = f.read().strip()
    except Exception:
        session = None

    if session:
        html_content = f"""
        <html>
            <body>
                <h3>Health: Ok</h3>
                <form action="/spid/logout" method="get">
                    <input type="hidden" name="session" value="{session}">
                    <button type="submit">Logout SPID</button>
                </form>
                <a href="/login">Login</a>
            </body>
        </html>
        """
    else:
        html_content = """
        <html>
            <body>
                <h3>Health: Ok</h3>
                <p>Nessuna sessione attiva.</p>
            </body>
            <a href="/login">Login</a>
            <a href="/spid/logout">Logout</a>
        </html>
        """

    return HTMLResponse(content=html_content)

# login route
app.include_router(login_router)

# spid routes
app.include_router(spid_router, prefix="/spid")