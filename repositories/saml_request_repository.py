# repositories/saml_request_repository.py
from database.models.saml_request import SAMLRequest

class SAMLRequestRepository:
    # GET
    @staticmethod
    def get_by_id(db, request_id):
        return db.query(SAMLRequest).filter(SAMLRequest.id == request_id).first()
    
    @staticmethod
    def get_by_request_id(db, request_id):
        return db.query(SAMLRequest).filter(SAMLRequest.request_id == request_id).first()
    
    # CREATE
    @staticmethod
    def create(db, request_id, session_id, request_type):
        new_request = SAMLRequest(
            request_id=request_id,
            session_id=session_id,
            request_type=request_type,
        )
        db.add(new_request)
        db.commit()
        db.refresh(new_request)
        return new_request
    
    # UPDATE
    @staticmethod
    def use_request(db, saml_request: SAMLRequest):
        if saml_request:
            saml_request.is_used = True
            db.commit()
            db.refresh(saml_request)
        return saml_request