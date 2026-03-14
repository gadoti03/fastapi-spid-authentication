# schemas/models.py
from pydantic import BaseModel # define and validate data using classes

class HealthResponse(BaseModel):
    status: str

class SpidLoginRequest(BaseModel):
    idp: str
    relay_state: str | None = None # Optional relay state