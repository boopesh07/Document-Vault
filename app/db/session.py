from collections.abc import AsyncGenerator

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings

database_url = make_url(settings.database_url)
query = dict(database_url.query)
if (database_url.host or "").endswith("supabase.co") and "sslmode" not in query:
    query["sslmode"] = "require"
    database_url = database_url.set(query=query)

engine = create_async_engine(
    database_url.render_as_string(hide_password=False),
    echo=False,
    pool_pre_ping=settings.database_pool_pre_ping,
    poolclass=NullPool,
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
