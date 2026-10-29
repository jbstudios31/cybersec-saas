from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.scan_run import ScanRun


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # low, medium, high, critical
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, resolved, false_positive
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())
    scan_run: Mapped["ScanRun"] = relationship(back_populates="findings")
