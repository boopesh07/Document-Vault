from uuid import UUID

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(component="AccessControlService")


class AccessControlService:
    """Temporary mock implementation that always authorizes the request."""

    async def is_authorized(self, user_id: UUID, action: str, resource_id: UUID | None = None) -> bool:
        if settings.access_control_allow_all:
            logger.debug("Access granted by mock", user_id=str(user_id), action=action, resource_id=str(resource_id))
            return True
        # Future: integrate with real access control microservice.
        logger.warning("Access denied (mock fallback)", user_id=str(user_id), action=action, resource_id=str(resource_id))
        return False
