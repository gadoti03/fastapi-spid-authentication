from fastapi import Request
from fastapi.responses import HTMLResponse
from spid.exceptions import (
    SpidConfigError,
    SpidSignatureError,
    SpidValidationError,
    SpidInternalError,
    MetadataNotFoundError,
    SessionError,
)
import logging

logger = logging.getLogger(__name__)

async def spid_config_error_handler(request: Request, exc: SpidConfigError):
    logger.error("SPID config error on %s: %s", request.url, exc)
    return HTMLResponse("SPID configuration error", status_code=500)

async def spid_signature_error_handler(request: Request, exc: SpidSignatureError):
    logger.error("SPID signature error on %s: %s", request.url, exc)
    return HTMLResponse("Authentication failed", status_code=400)

async def spid_validation_error_handler(request: Request, exc: SpidValidationError):
    logger.error("SPID validation error on %s: %s", request.url, exc)
    return HTMLResponse("Authentication failed", status_code=400)

async def spid_internal_error_handler(request: Request, exc: SpidInternalError):
    logger.error("SPID internal error on %s: %s", request.url, exc)
    return HTMLResponse("Internal server error", status_code=500)

async def metadata_not_found_error_handler(request: Request, exc: MetadataNotFoundError):
    logger.error("Metadata not found error on %s: %s", request.url, exc)
    return HTMLResponse("Metadata file not found", status_code=404)

async def session_error_handler(request: Request, exc: SessionError):
    logger.error("Session error on %s: %s", request.url, exc)
    return HTMLResponse("Session problem", status_code=400)