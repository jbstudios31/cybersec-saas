"""Modelos base: re-export de Base para que Alembic y la app usen el mismo registry."""

from app.core.database import Base

__all__ = ["Base"]
