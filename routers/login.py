from fastapi import APIRouter
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/login", response_class=Response) # response_class=Response: avoid default JSON response
async def login(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})
    #return Response(content="Login endpoint - to be implemented", status_code=200)