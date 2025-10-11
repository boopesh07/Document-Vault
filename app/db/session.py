from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import AsyncAdaptedQueuePool

from app.core.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
    poolclass=AsyncAdaptedQueuePool,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
)

AsyncSessionFactory = async_sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionFactory() as session:
        try:
            yield session
        finally:
            await session.close()
