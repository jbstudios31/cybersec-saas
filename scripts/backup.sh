#!/bin/sh
set -e

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILE="/backups/cybersec_${TIMESTAMP}.sql.gz"

pg_dump \
  -h "${PGHOST:-postgres}" \
  -U "${PGUSER:-cybersec}" \
  -d "${PGDATABASE:-cybersec}" \
  --no-owner --no-privileges \
  | gzip > "$FILE"

# Verificación de integridad: el dump debe ser gzip válido y no estar vacío
if [ ! -s "$FILE" ] || ! gzip -t "$FILE" 2>/dev/null; then
    echo "ERROR: backup corrupto o vacío: $FILE" >&2
    rm -f "$FILE"
    exit 1
fi

# Retención configurable (por defecto 7 días)
find /backups -name 'cybersec_*.sql.gz' -mtime "+${BACKUP_RETENTION_DAYS:-7}" -delete

echo "Backup creado correctamente: $FILE ($(du -h "$FILE" | cut -f1))"
