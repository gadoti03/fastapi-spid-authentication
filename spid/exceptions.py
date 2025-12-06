class SpidConfigError(Exception):
    """wrong config  (missing file, missing params, unknown idp)"""
    pass

class SpidSignatureError(Exception):
    """errors in signing or loading key"""
    pass

class SpidValidationError(Exception):
    """errors in validating the response / signature"""
    pass

class SpidInternalError(Exception):
    """unexpected errors"""
    pass
