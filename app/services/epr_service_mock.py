from __future__ import annotations

from uuid import UUID

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(component="EprServiceMock")


class EprServiceMock:
    """
    A mock service that simulates the future Entity & Permissions Core (EPR).
    
    Supports role-based authorization for testing purposes. Can be configured
    with a role mapping to simulate different user permissions.
    """
    
    def __init__(self, role_permissions: dict[UUID, str] | None = None) -> None:
        """
        Initialize the EPR mock service.
        
        Args:
            role_permissions: Optional mapping of user_id to role name.
                            Roles: 'admin', 'issuer', 'investor', 'auditor'
                            If provided (even if empty), uses role-based authorization.
                            If None, defaults to granting all access when EPR_MOCK_MODE=true.
        """
        self.role_permissions = role_permissions
        self.use_role_based_auth = role_permissions is not None
        
    async def is_authorized(
        self, *, user_id: UUID, action: str, resource_id: UUID, principal_type: str = "user"
    ) -> bool:
        if settings.epr_mock_mode:
            # If role_permissions provided, use role-based authorization
            if self.use_role_based_auth:
                role = self.role_permissions.get(user_id)  # type: ignore
                is_allowed = self._check_role_permission(role, action)
                
                logger.info(
                    "EPR mock role-based authorization",
                    user_id=str(user_id),
                    role=role,
                    action=action,
                    resource_id=str(resource_id),
                    allowed=is_allowed,
                )
                return is_allowed
            
            # Default behavior: grant access
            logger.warning(
                "EPR mock is enabled. Granting access by default.",
                user_id=str(user_id),
                action=action,
                resource_id=str(resource_id),
                principal_type=principal_type,
            )
            return True

        # In a real scenario, this would involve a network call to the EPR service.
        logger.info(
            "EPR mock is disabled. Denying access by default.",
            user_id=str(user_id),
            action=action,
            resource_id=str(resource_id),
        )
        return False
    
    def _check_role_permission(self, role: str | None, action: str) -> bool:
        """
        Check if a role has permission for an action.
        
        Role permissions:
        - admin: All actions
        - issuer: upload, download, verify, archive
        - investor: download (read-only)
        - auditor: download, verify (read + verify)
        - compliance_officer: download, verify, archive (read + verify + admin actions, NO upload)
        - None: No permissions
        """
        if role is None:
            return False
        
        role = role.lower()
        
        # Admin has all permissions
        if role == "admin":
            return True
        
        # Define role-based permissions
        role_actions = {
            "issuer": {"document:upload", "document:download", "document:verify", "document:archive"},
            "investor": {"document:download"},
            "auditor": {"document:download", "document:verify"},
            "compliance_officer": {"document:download", "document:verify", "document:archive"},
        }
        
        allowed_actions = role_actions.get(role, set())
        return action in allowed_actions
