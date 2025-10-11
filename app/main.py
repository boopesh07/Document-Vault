from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.router import api_router
from app.core.config import settings
from app.core.logger import configure_logging, get_logger
from app.services.document_service import DocumentNotFoundError

configure_logging()
logger = get_logger(component="FastAPI")


def create_app() -> FastAPI:
    app = FastAPI(title=settings.project_name, version="1.0.0")

    @app.exception_handler(DocumentNotFoundError)
    async def handle_not_found(_: Request, exc: DocumentNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    app.include_router(api_router, prefix=settings.api_v1_prefix)

    @app.get("/healthz", tags=["health"])
    async def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
