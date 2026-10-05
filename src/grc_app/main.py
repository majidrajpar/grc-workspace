"""Run the local GRC workspace."""

from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from grc_app.db import connect, init_db
from grc_app.web import install_handlers, router

STATIC = Path(__file__).parent / "static"


def default_db_path() -> Path:
    return Path(os.environ.get("GRC_DB", "data/grc.sqlite"))


def session_secret(db_path: Path) -> str:
    configured = os.environ.get("GRC_SESSION_SECRET")
    if configured:
        return configured
    key_path = db_path.parent / "session.key"
    if key_path.exists():
        return key_path.read_text(encoding="utf-8").strip()
    secret = secrets.token_hex(32)
    key_path.write_text(secret, encoding="utf-8")
    return secret


def create_app(db_path: Path | None = None) -> FastAPI:
    path = db_path or default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        conn = connect(app.state.db_path)
        init_db(conn)
        conn.commit()
        conn.close()
        yield

    app = FastAPI(title="GRC workspace", lifespan=lifespan)
    app.state.db_path = path
    from starlette.middleware.sessions import SessionMiddleware

    app.add_middleware(SessionMiddleware, secret_key=session_secret(path), same_site="lax")
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    app.include_router(router)
    install_handlers(app)
    return app


def main() -> None:
    import uvicorn

    uvicorn.run(
        create_app(),
        host=os.environ.get("GRC_HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
    )
