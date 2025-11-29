from fastapi import APIRouter
from fastapi.responses import Response

router = APIRouter()

@router.get("/login", response_class=Response) # response_class=Response: avoid default JSON response
async def login():
    return Response(content="Login endpoint - to be implemented", status_code=200)