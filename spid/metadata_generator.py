import os
from fastapi import APIRouter, Response
from fastapi.responses import FileResponse

router = APIRouter()

METADATA_FILE = os.path.join(os.path.dirname(__file__), "metadata.xml")

@router.get("/metadata", response_class=Response) # response_class=Response: avoid default JSON response
async def get_metadata():
    if os.path.exists(METADATA_FILE):
        return FileResponse(METADATA_FILE, media_type="application/samlmetadata+xml")
    else:
        return Response(content="Metadata non trovato", status_code=404)
