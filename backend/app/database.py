"""
Contexta Backend - Database Module

This module handles database connection, session management, and base model configuration.
Uses SQLAlchemy with async support for PostgreSQL.
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings

# Determine if using SQLite
is_sqlite = settings.database_url.startswith("sqlite")

# Async engine for FastAPI
if is_sqlite:
    # SQLite doesn't support pool_size/max_overflow
    async_engine = create_async_engine(
        settings.database_url,
        echo=settings.debug,
    )
else:
    async_engine = create_async_engine(
        settings.database_url,
        echo=settings.debug,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

# Sync engine for Alembic migrations
sync_engine = create_engine(
    settings.database_sync_url,
    echo=settings.debug,
    pool_pre_ping=True,
)

# Sync session factory
SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    autoflush=False,
    autocommit=False,
)

# Declarative base for models
Base = declarative_base()


_db_available = True

async def get_db():
    """
    Dependency that provides a database session.
    Yields None if the database is unavailable (e.g. no PostgreSQL running).
    """
    global _db_available
    if not _db_available:
        yield None
        return
    
    try:
        session = AsyncSessionLocal()
    except Exception:
        _db_available = False
        yield None
        return
    
    try:
        yield session
        try:
            await session.commit()
        except Exception:
            _db_available = False
    except Exception:
        try:
            await session.rollback()
        except Exception:
            _db_available = False
        raise
    finally:
        try:
            await session.close()
        except Exception:
            _db_available = False


async def init_db() -> None:
    """
    Initialize database tables.
    
    Creates all tables defined in the models.
    Should be called on application startup.
    """
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """
    Close database connections.
    
    Should be called on application shutdown.
    """
    await async_engine.dispose()
