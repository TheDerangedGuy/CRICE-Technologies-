"""
app/cases/routes.py – stub registered in Phase 2 so auth tests pass.
Full implementation in Phase 3.
"""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from app.auth.roles import get_current_user
from app.models import User

router = APIRouter(tags=["cases"])


@router.get("/cases", response_model=None)
def cases_list_stub(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Response:
    # Stub: returns 200 so auth tests can verify that a full session reaches /cases.
    # Replaced with full implementation in Phase 3.
    from fastapi.responses import HTMLResponse
    return HTMLResponse("<p>Cases (stub – Phase 3 will replace this)</p>")


@router.get("/cases/new", response_model=None)
def cases_new_stub(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Response:
    from fastapi.responses import HTMLResponse
    return HTMLResponse("<p>New case (stub – Phase 3)</p>")
