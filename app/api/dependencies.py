from fastapi import Depends

from app.events.publisher import DocumentEventPublisher
from app.services.access_control import AccessControlService
from app.services.audit_service import AuditService
from app.services.blockchain_service import BlockchainService
from app.services.document_service import DocumentService
from app.services.hashing_service import HashingService
from app.services.storage_service import StorageService

_storage_service = StorageService()
_hashing_service = HashingService()
_audit_service = AuditService()
_access_control_service = AccessControlService()
_blockchain_service = BlockchainService()
_event_publisher = DocumentEventPublisher()
_document_service = DocumentService(
    storage_service=_storage_service,
    hashing_service=_hashing_service,
    audit_service=_audit_service,
    access_control_service=_access_control_service,
    blockchain_service=_blockchain_service,
    event_publisher=_event_publisher,
)


def get_document_service() -> DocumentService:
    return _document_service
