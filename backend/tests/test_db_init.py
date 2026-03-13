
import asyncio
import structlog
from app.database import init_db, async_engine
from app.models import cve, user, asset, log, risk, incident, ledger, playbook

async def test():
    print("Initializing database...")
    try:
        await init_db()
        print("Database initialized successfully!")
    except Exception as e:
        print(f"Database initialization failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test())
