import os
import asyncpg
import logging
from typing import Optional

logger = logging.getLogger("sentineltrust.db")

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_USER = os.getenv("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
POSTGRES_DB = os.getenv("POSTGRES_DB", "sentineltrust_db")

pool: Optional[asyncpg.Pool] = None

async def init_db_pool() -> asyncpg.Pool:
    global pool
    if pool is not None:
        try:
            await pool.close()
        except Exception:
            pass
        pool = None

    pool = await asyncpg.create_pool(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
        database=POSTGRES_DB,
        min_size=2,
        max_size=20
    )
    logger.info("Connected to PostgreSQL (sentineltrust_db)")
    return pool

async def get_db_pool() -> asyncpg.Pool:
    global pool
    if pool is None:
        await init_db_pool()
    return pool

async def close_db_pool():
    global pool
    if pool is not None:
        try:
            await pool.close()
        except Exception:
            pass
        pool = None
