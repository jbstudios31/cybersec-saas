---
title: Cybersec SaaS
emoji: 🛡️
colorFrom: blue
colorTo: gray
sdk: docker
app_port: 8000
pinned: false
---

# Cybersec SaaS

MVP de plataforma SaaS de ciberseguridad: escaneo de objetivos (cabeceras de seguridad, TLS, rutas expuestas), gestión de hallazgos, reportes PDF y API REST para apps móviles.

## Stack

- FastAPI + Jinja2 (UI web HTML)
- SQLAlchemy 2 + Alembic (PostgreSQL / Supabase)
- Celery + Redis (cola de escaneos, opcional en free tier)
- Scanner propio (`scanner/checks.py`) sobre `requests`
- Reportes PDF con ReportLab
- Métricas Prometheus (`/metrics`)

## Estructura

```
app/
  main.py          # rutas HTML, middleware, arranque
  api/routes.py    # API REST
  api/deps.py      # autenticación (sesión HTML + JWT)
  core/            # config, DB, JWT, CSRF, SSRF, rate limit, seguridad
  models/          # User, Target, ScanRun, Finding
  templates/       # UI web (login, panel, target, admin)
worker/            # Celery tasks, beat, alertas email
scanner/checks.py  # lógica de escaneo
alembic/           # migraciones
tests/             # pytest
```

## Variables de entorno

Copia `.env.example` a `.env` (no se versiona).

| Variable | Descripción |
|---|---|
| `ENV` | `development` / `production` (en producción exige `SECRET_KEY` real y cookies HTTPS) |
| `SECRET_KEY` | Clave de sesiones y JWT |
| `CORS_ORIGINS` | Orígenes permitidos, separados por coma |
| `DATABASE_URL` | `postgresql+psycopg2://usuario:pass@host:5432/db?sslmode=require` |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | Pool de conexiones (default 5 / 10) |
| `DB_SSLMODE` | Fuerza SSL (auto con Supabase) |
| `REDIS_URL` | Broker/result backend de Celery |
| `SCAN_ASYNC` | `true` encola en Celery; `false` escanea en el request |
| `CRON_TOKEN` | Token para `POST /cron/scan-next` |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Crea el admin inicial al arrancar (opcional) |
| `SMTP_*`, `ALERT_EMAIL` | Envío de alertas por email |

## Puesta en marcha (local)

```bash
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

UI: http://localhost:8000 · API docs: http://localhost:8000/docs · Métricas: `/metrics`

Tests:

```bash
pytest tests/ -v
```

## Despliegue gratuito (sin tarjeta)

El modo free tier usa **escaneo síncrono** y un **cron externo** en lugar de Celery worker/beat.

1. `SCAN_ASYNC=false` y `CRON_TOKEN=<token aleatorio>` en las variables de entorno.
2. Despliega solo el servicio web (Koyeb, Render free, Hugging Face Spaces o PythonAnywhere).
3. Configura el cron externo (cron-job.org, gratuito) cada 5–10 min:

```
POST https://TU-DOMAIN/cron/scan-next
Header: X-Cron-Token: <CRON_TOKEN>
```

El endpoint escanea el target activo cuyo último escaneo es más antiguo (o que nunca se escaneó) y devuelve `{scanned, target_id, result}`.

Con Supabase: usa la URI de conexión (Settings → Database) como `DATABASE_URL` con `?sslmode=require`. Si usas el pooler (puerto 6543), el código desactiva prepared statements automáticamente.

### Render (blueprint incluido)

1. Sube el repo a GitHub.
2. En Render: **New → Blueprint** → selecciona el repo (detecta `render.yaml`).
3. Rellena las variables marcadas `sync: false`: `DATABASE_URL` (Supabase), `CORS_ORIGINS`, `TRUSTED_HOSTS`, `ADMIN_EMAIL`.
4. Render genera `SECRET_KEY`, `CRON_TOKEN` y `ADMIN_PASSWORD` automáticamente.
5. El `preDeployCommand` ejecuta `alembic upgrade head` en cada despliegue.

Después añade el cron en cron-job.org apuntando a `https://<tu-servicio>.onrender.com/cron/scan-next` con el header `X-Cron-Token`.

### Hugging Face Spaces

Crea un Space con SDK **Docker**, sube el repo y define en *Settings → Variables and secrets*:
`DATABASE_URL`, `SECRET_KEY`, `ENV=production`, `SCAN_ASYNC=false`, `CRON_TOKEN`.
El `app_port` ya viene declarado en el frontmatter de este README.

### Con Docker (todo incluido)

```bash
cp .env.example .env   # y rellena SECRET_KEY / DATABASE_URL
docker compose up -d --build
```

El servicio `app` ejecuta `alembic upgrade head` antes de arrancar. Servicios: `app`, `worker`, `beat`, `redis`, `nginx` (TLS), `prometheus`, `backup` (dump diario verificado, retención configurable).

Health checks: `/health` (liveness) y `/ready` (verifica la DB).

## API REST (app móvil)

Autenticación JWT:

```
POST /auth/token          (form: username, password)  -> {access_token, token_type}
```

Enviar `Authorization: Bearer <token>`. Endpoints: `/users`, `/targets`, `/targets/{id}/scans`, `/scans/{id}/findings`, `PATCH /findings/{id}/status`, `/targets/{id}/scan`, `/targets/{id}/report` (PDF).

## Observabilidad

- Logs estructurados en JSON (producción) con `request_id` por petición; en texto plano en desarrollo.
- Cabecera `X-Request-ID` (respeta el `X-Request-ID` entrante) y `X-Response-Time-ms`.
- Métricas Prometheus en `/metrics` (instrumentación automática de FastAPI).
- `GET /metrics` bloqueado en nginx; exposition restringida a la red interna.

## Seguridad implementada

- CSRF en todos los formularios HTML.
- SSRF: bloqueo de IPs privadas/reservadas, IPv4-mapped IPv6, hosts `.local`, sin seguir redirecciones y revalidación antes de cada escaneo.
- Cookies de sesión `HttpOnly` + `SameSite=Lax` + `Secure` en producción.
- Política de contraseñas (mín. 10 chars, mayúscula, minúscula, número) y PBKDF2-HMAC-SHA256 con 310k iteraciones versionadas.
- Rate limiting de login distribuido con Redis (fallback en memoria) y límite en la API JWT.
- JWT con `iss`, `aud`, `jti`, `typ` y expiración configurable.
- Cabeceras de seguridad, HSTS en producción, `TrustedHostMiddleware`, `CORS` explícito.
- Auditoría de acciones sensibles en la tabla `audit_logs`.
- `create_all` desactivado en producción (solo Alembic).
- Escaneo de dependencias (`pip-audit`) en CI.
- Passwords con PBKDF2-HMAC-SHA256 y salt por usuario.
- Rate limit de login, cabeceras de seguridad, HSTS en producción.
- Escaneo de dependencias (`pip-audit`) en CI.
