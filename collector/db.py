import os
import logging
from pathlib import Path
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from collector.models import Base

logger = logging.getLogger(__name__)

DEFAULT_DATABASE_URL = "postgresql+asyncpg://threatscope:threatscope@localhost:5432/threatscope"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)

# Normalize relative sqlite URLs so reads/writes always hit the same file
# even if the API is started from a different working directory.
if DATABASE_URL.startswith("sqlite+aiosqlite:///./"):
    sqlite_name = DATABASE_URL.removeprefix("sqlite+aiosqlite:///./")
    sqlite_path = (Path(__file__).resolve().parent.parent / sqlite_name).as_posix()
    DATABASE_URL = f"sqlite+aiosqlite:///{sqlite_path}"

engine_kwargs = {"echo": False}
if not DATABASE_URL.startswith("sqlite+aiosqlite://"):
    engine_kwargs.update({"pool_size": 10, "max_overflow": 20})

engine = create_async_engine(DATABASE_URL, **engine_kwargs)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created.")


async def get_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


async def close_db():
    await engine.dispose()
    logger.info("Database engine disposed.")
