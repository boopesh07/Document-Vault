from __future__ import annotations

from uuid import UUID

import httpx

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(component="EprService")


class EprService:
    """
    Client for the Entity & Permissions Core (EPR) service.
    
    This service handles authorization checks by making HTTP calls to the EPR service.
    When EPR_MOCK_MODE is enabled, use EprServiceMock instead.
    """

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self.http_client = http_client
        self.base_url = str(settings.epr_service_url) if settings.epr_service_url else None
        self.timeout = settings.epr_service_timeout

    async def is_authorized(
        self, *, user_id: UUID, action: str, resource_id: UUID, principal_type: str = "user"
    ) -> bool:
        """
        Check if a user is authorized to perform an action on a resource.

        Args:
            user_id: UUID of the user requesting access
            action: The action being requested (e.g., "document:upload")
            resource_id: UUID of the resource being accessed
            principal_type: Type of principal (default: "user")

        Returns:
            bool: True if authorized, False otherwise

        Raises:
            Exception: If the EPR service is unavailable or returns an error
        """
        if not self.base_url:
            logger.error("EPR service URL not configured")
            return False

        try:
            response = await self.http_client.post(
                f"{self.base_url}/api/v1/permissions/check",
                json={
                    "principal_id": str(user_id),
                    "principal_type": principal_type,
                    "action": action,
                    "resource_id": str(resource_id),
                },
                timeout=self.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                is_allowed = data.get("allowed", False)
                logger.info(
                    "EPR authorization check",
                    user_id=str(user_id),
                    action=action,
                    resource_id=str(resource_id),
                    allowed=is_allowed,
                )
                return is_allowed
            else:
                logger.warning(
                    "EPR service returned non-200 status",
                    status_code=response.status_code,
                    user_id=str(user_id),
                    action=action,
                )
                return False

        except httpx.TimeoutException:
            logger.error(
                "EPR service timeout",
                user_id=str(user_id),
                action=action,
                timeout=self.timeout,
            )
            return False
        except Exception as e:
            logger.error(
                "EPR service error",
                user_id=str(user_id),
                action=action,
                error=str(e),
            )
            return False
