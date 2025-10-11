from typing import Any

from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column
from sqlalchemy.sql import func
from sqlalchemy.types import DateTime


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[Any] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class PrimaryKeyUUIDMixin:
    @declared_attr.directive
    def id(cls) -> Mapped[Any]:
        from uuid import uuid4

        from app.models.types import GUID

        return mapped_column(GUID(), primary_key=True, default=uuid4)
