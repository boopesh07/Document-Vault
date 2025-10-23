from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.dependencies import get_document_service
from app.api.router import api_router
from app.core.config import settings
from app.core.logger import configure_logging, get_logger
from app.services.document_service import DocumentNotFoundError
from app.workers.document_vault_consumer import build_consumer_from_env

configure_logging()
logger = get_logger(component="FastAPI")

# Global reference to consumer for graceful shutdown
_consumer_task: asyncio.Task | None = None
_consumer_instance = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle: start background consumer on startup, stop on shutdown."""
    global _consumer_task, _consumer_instance

    # Startup: Initialize and start consumer
    try:
        document_service = get_document_service()
        consumer = build_consumer_from_env(document_service)

        if consumer:
            _consumer_instance = consumer
            _consumer_task = asyncio.create_task(consumer.run_forever())
            logger.info("Document Vault consumer started as background task")
        else:
            logger.info("Document Vault consumer not started (disabled or not configured)")
    except Exception as exc:
        logger.exception("Failed to start Document Vault consumer", error=str(exc))

    yield  # Application runs here

    # Shutdown: Stop consumer gracefully
    if _consumer_instance and _consumer_task:
        logger.info("Shutting down Document Vault consumer")
        try:
            await _consumer_instance.shutdown()
            _consumer_task.cancel()
            try:
                await _consumer_task
            except asyncio.CancelledError:
                pass
            logger.info("Document Vault consumer shutdown complete")
        except Exception as exc:
            logger.exception("Error during consumer shutdown", error=str(exc))


def create_app() -> FastAPI:
    app = FastAPI(title=settings.project_name, version="1.0.0", lifespan=lifespan)

    @app.exception_handler(DocumentNotFoundError)
    async def handle_not_found(_: Request, exc: DocumentNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    app.include_router(api_router, prefix=settings.api_v1_prefix)

    @app.get("/healthz", tags=["health"])
    async def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
