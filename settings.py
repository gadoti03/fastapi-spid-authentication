from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # DATABASE
    DATABASE_URL: str

    # PATH SETTINGS
    IDPS_FILE: str
    METADATA_FILE: str

    # SPID SETTINGS
    COMMON_NAME: str
    DAYS: int
    ENTITY_ID: str
    NAME_QUALIFIER: str
    ACS_URL: str
    KEY_LEN: int
    LOCALITY_NAME: str
    MD_ALG: str
    ORGANIZATION_IDENTIFIER: str
    ORGANIZATION_NAME: str

    # OTHER SETTINGS
    URL_ROOT: str

    # METADATA SETTINGS
    CERT_DIR_PATH: str
    METADATA_PATH: str
    METADATA_CLEAN_PATH: str

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()