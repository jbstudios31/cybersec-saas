from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from app.api.deps import DbSession, get_current_user
from app.api.schemas import (
    FindingList,
    FindingOut,
    FindingStatusUpdate,
    ScanRunOut,
    TargetCreate,
    TargetList,
    TargetOut,
    Token,
    UserCreate,
    UserOut,
    normalize_email,
)
from app.core import config
from app.core.jwt import create_access_token
from app.core.logging import logger
from app.core.rate_limit import check_rate_limit, record_failed_attempt, reset_attempts
from app.core.security import (
    WeakPasswordError,
    get_user_by_email,
    hash_password,
    validate_password_strength,
    verify_password,
)
from app.core.ssrf import validate_target_url
from app.models.finding import Finding
from app.models.scan_run import ScanRun
from app.models.target import Target
from app.models.user import User
from app.reports import build_pdf_report
from worker.tasks import execute_scan, run_scan

router = APIRouter()


# ---- Auth (JWT) ----

@router.post("/auth/token", response_model=Token)
async def login_for_access_token(request: Request, db: DbSession):
    form = await request.form()
    email = form.get("username") or form.get("email")
    password = form.get("password")
    if not email or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="email y password requeridos")
    email = str(email).strip().lower()
    check_rate_limit(email)
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.password_hash, user.password_salt):
        record_failed_attempt(email)
        logger.warning("login_fallido", extra={"email": email, "origen": "api"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario desactivado")
    reset_attempts(email)
    access_token = create_access_token(data={"sub": user.email})
    logger.info("login_ok", extra={"email": email, "origen": "api", "user_id": user.id})
    return {"access_token": access_token, "token_type": "bearer"}


# ---- Users ----

@router.post("/users", response_model=UserOut, status_code=201)
def create_user(payload: UserCreate, db: DbSession, current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Solo administradores pueden crear usuarios")
    try:
        email = normalize_email(payload.email)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="email inválido") from exc
    try:
        validate_password_strength(payload.password)
    except WeakPasswordError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    existing = get_user_by_email(db, email)
    if existing:
        raise HTTPException(status_code=400, detail="email ya registrado")
    pwd_hash, pwd_salt = hash_password(payload.password)
    user = User(
        email=email,
        password_hash=pwd_hash,
        password_salt=pwd_salt,
        is_admin=payload.is_admin,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("usuario_creado", extra={"actor_id": current_user.id, "target_user_id": user.id, "is_admin": user.is_admin})
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(db: DbSession, current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Solo administradores pueden listar usuarios")
    return db.query(User).all()


# ---- Targets ----

@router.post("/targets", response_model=TargetOut, status_code=201)
def create_target(payload: TargetCreate, db: DbSession, current_user: User = Depends(get_current_user)):
    if not current_user.is_admin and payload.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No puedes crear targets para otro usuario")
    if not db.get(User, payload.owner_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="propietario no encontrado")
    validate_target_url(payload.url)
    target = Target(name=payload.name, url=payload.url, owner_id=payload.owner_id)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("/targets", response_model=TargetList)
def list_targets(
    db: DbSession,
    current_user: User = Depends(get_current_user),
    page: int = 1,
    page_size: int = 20,
):
    query = db.query(Target)
    if not current_user.is_admin:
        query = query.filter(Target.owner_id == current_user.id)
    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    pages = (total + page_size - 1) // page_size if total else 0
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": pages}


@router.get("/targets/{target_id}", response_model=TargetOut)
def get_target(target_id: int, db: DbSession, current_user: User = Depends(get_current_user)):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    if not current_user.is_admin and target.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tienes acceso a este target")
    return target


@router.get("/targets/{target_id}/scans", response_model=list[ScanRunOut])
def list_scans(target_id: int, db: DbSession, current_user: User = Depends(get_current_user)):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    if not current_user.is_admin and target.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tienes acceso a este target")
    return db.query(ScanRun).filter(ScanRun.target_id == target_id).all()


@router.get("/scans/{scan_id}/findings", response_model=FindingList)
def list_findings(
    scan_id: int,
    db: DbSession,
    current_user: User = Depends(get_current_user),
    page: int = 1,
    page_size: int = 20,
):
    scan = db.get(ScanRun, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    target = db.get(Target, scan.target_id)
    if not current_user.is_admin and target.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tienes acceso a este escaneo")
    query = db.query(Finding).filter(Finding.scan_run_id == scan_id)
    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    pages = (total + page_size - 1) // page_size if total else 0
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": pages}


@router.patch("/findings/{finding_id}/status", response_model=FindingOut)
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    db: DbSession,
    current_user: User = Depends(get_current_user),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="hallazgo no encontrado")
    scan = db.get(ScanRun, finding.scan_run_id)
    target = db.get(Target, scan.target_id)
    if not current_user.is_admin and target.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tienes acceso a este hallazgo")
    if payload.status not in ("pending", "resolved", "false_positive"):
        raise HTTPException(status_code=400, detail="estado inválido")
    finding.status = payload.status
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/targets/{target_id}/report")
def download_report(target_id: int, db: DbSession, current_user: User = Depends(get_current_user)):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    if not current_user.is_admin and target.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tienes acceso a este target")

    # Obtener hallazgos del último escaneo del target
    latest_scan = (
        db.query(ScanRun)
        .filter(ScanRun.target_id == target.id)
        .order_by(ScanRun.started_at.desc())
        .first()
    )
    findings = []
    if latest_scan:
        findings = (
            db.query(Finding)
            .filter(Finding.scan_run_id == latest_scan.id)
            .all()
        )

    findings_data = [
        {
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "remediation": f.remediation,
        }
        for f in findings
    ]

    pdf = build_pdf_report(
        target_name=target.name,
        target_url=target.url,
        owner_id=target.owner_id,
        findings=findings_data,
    )

    return StreamingResponse(
        iter([pdf]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="reporte-{target.name.replace(" ", "-").replace(chr(34), "")}.pdf"'},
    )


@router.post("/targets/{target_id}/scan", status_code=202)
def trigger_scan(target_id: int, db: DbSession, current_user: User = Depends(get_current_user)):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    if not current_user.is_admin and target.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tienes acceso a este target")
    validate_target_url(target.url)

    if config.SCAN_ASYNC:
        try:
            async_result = run_scan.delay(target_id)
            return {"accepted": True, "target_id": target_id, "task_id": async_result.id}
        except Exception:  # noqa: BLE001 - sin broker/worker, ejecutar síncrono
            pass

    result = execute_scan(target_id)
    return {"accepted": True, "target_id": target_id, "scan": result}
