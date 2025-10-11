from uuid import UUID

from app.core.logger import get_logger

logger = get_logger(component="BlockchainService")


class BlockchainService:
    async def register_document(self, *, token_id: int | None, document_hash: str, metadata_uri: str | None) -> str:
        """Mock blockchain integration that logs the registration and returns a fake tx id."""
        tx_id = f"tx-{document_hash[:16]}"
        logger.info(
            "Mock register_document",
            token_id=token_id,
            document_hash=document_hash,
            metadata_uri=metadata_uri,
            tx_id=tx_id,
        )
        return tx_id

    async def verify_document(self, *, document_id: UUID, document_hash: str) -> bool:
        logger.info("Mock verify_document", document_id=str(document_id), document_hash=document_hash)
        return True
