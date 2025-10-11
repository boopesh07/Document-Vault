from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import AsyncAdaptedQueuePool, NullPool

from app.core.config import settings

engine_options: dict[str, object] = {
    "echo": False,
    "pool_pre_ping": settings.database_pool_pre_ping,
}

if settings.database_url.startswith("sqlite+"):
    engine_options["poolclass"] = NullPool
else:
    engine_options["poolclass"] = AsyncAdaptedQueuePool
    engine_options["pool_size"] = settings.database_pool_size
    engine_options["max_overflow"] = settings.database_max_overflow

engine = create_async_engine(settings.database_url, **engine_options)

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
