"""
app/templates_config.py – single Jinja2Templates instance shared by all routers.
Import `templates` from here to avoid circular imports.
"""
from pathlib import Path

from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
