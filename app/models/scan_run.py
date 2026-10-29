from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.target import Target


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, done, failed
    started_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=True)
    target: Mapped["Target"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_run")
