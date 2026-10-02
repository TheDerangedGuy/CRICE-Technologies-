"""
app/main.py – FastAPI application factory.
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.auth.middleware import SessionMiddleware
from app.auth import routes as auth_routes
from app.cases import routes as cases_routes

app = FastAPI(
    title="CRICE Lab",
    docs_url=None,
    redoc_url=None,
)

# ── Middleware ────────────────────────────────────────────────────────────────
app.add_middleware(SessionMiddleware)

# ── Static files ─────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_routes.router)
app.include_router(cases_routes.router)

# ── Exception handlers ────────────────────────────────────────────────────────

@app.exception_handler(401)
async def auth_required_handler(request: Request, exc) -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=302)


@app.exception_handler(403)
async def forbidden_handler(request: Request, exc) -> HTMLResponse:
    return HTMLResponse(
        "<h1>403 – Forbidden</h1>"
        "<p>You don't have permission to do that.</p>"
        "<p><a href='/cases'>Back to Cases</a></p>",
        status_code=403,
    )


# ── Root redirect ─────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/cases", status_code=302)
