from fastapi import FastAPI
from database.connection import engine, Base

from routers.login import router as login_router
from routers.spid import router as spid_router

from fastapi.middleware.cors import CORSMiddleware

from schemas.models import HealthResponse

from fastapi import APIRouter
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
    
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

# root route
@app.get("/", response_model=HealthResponse) # response_model=HealthResponse: define the response schema
async def health():
    return HealthResponse(status="Ok")

# login route
app.include_router(login_router)

# spid routes
app.include_router(spid_router, prefix="/spid")