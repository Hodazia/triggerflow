from contextlib import asynccontextmanager
import uvicorn
from fastapi import FastAPI

from src.api.api_keys import router as api_keys_router
from src.core.security import seed_bootstrap_key
from src.core.database import Base, engine, SessionLocal
from src.core.config import settings
from dotenv import load_dotenv

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Development convenience only.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with SessionLocal() as db:
        await seed_bootstrap_key(
            db,
            settings.bootstrap_api_key,
        )

    yield

    await engine.dispose()


app = FastAPI(
    title="TriggerFlow API",
    description="A background job execution platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(api_keys_router)

@app.get("/health/live", tags=["Health"])
async def liveness():
    return {"status": "alive"}


@app.get("/health/ready", tags=["Health"])
async def readiness():
    # Basic DB check; this can be expanded to verify
    # other required dependencies.
    from sqlalchemy import text

    async with SessionLocal() as db:
        await db.execute(text("SELECT 1"))

    return {"status": "ready"}



def main():
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()