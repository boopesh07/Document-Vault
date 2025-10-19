from __future__ import annotations

from uuid import UUID

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(component="EprServiceMock")


class EprServiceMock:
    """A mock service that simulates the future Entity & Permissions Core (EPR)."""

    async def is_authorized(
        self, *, user_id: UUID, action: str, resource_id: UUID, principal_type: str = "user"
    ) -> bool:
        if settings.epr_mock_mode:
            logger.warning(
                "EPR mock is enabled. Granting access by default.",
                user_id=str(user_id),
                action=action,
                resource_id=str(resource_id),
                principal_type=principal_type,
            )
            return True

        # In a real scenario, this would involve a network call to the EPR service.
        # The mock can be extended here to simulate more complex RBAC rules.
        logger.info(
            "EPR mock is disabled. Denying access by default.",
            user_id=str(user_id),
            action=action,
            resource_id=str(resource_id),
        )
        return False
