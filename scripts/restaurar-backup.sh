#!/usr/bin/env bash

set -euo pipefail
umask 0077

DIRECTORIO_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/lib/operaciones-comunes.sh
. "${DIRECTORIO_SCRIPT}/lib/operaciones-comunes.sh"

ROL=""
BACKUP=""
NO_INICIAR=false

mostrar_uso() {
    cat <<'EOF'
Uso:
  sudo ./scripts/restaurar-backup.sh --role central --backup /ruta/backup [--no-start]
  sudo ./scripts/restaurar-backup.sh --role agent --backup /ruta/backup [--no-start]
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)
            [[ $# -ge 2 ]] || { mostrar_uso >&2; error "--role requiere un valor."; }
            ROL="$2"
            shift 2
            ;;
        --backup)
            [[ $# -ge 2 ]] || { mostrar_uso >&2; error "--backup requiere una ruta."; }
            BACKUP="$2"
            shift 2
            ;;
        --no-start)
            NO_INICIAR=true
            shift
            ;;
        -h|--help)
            mostrar_uso
            exit 0
            ;;
        *)
            mostrar_uso >&2
            error "argumento no reconocido: $1"
            ;;
    esac
done

validar_rol "${ROL}"
[[ -n "${BACKUP}" ]] || { mostrar_uso >&2; error "debe indicar --backup."; }
[[ "${BACKUP}" == /* ]] || error "--backup debe ser una ruta absoluta."
requerir_root
validar_ubuntu
requerir_comando systemctl
requerir_comando install
PYTHON="$(python_instalado)"
validar_backup "${ROL}" "${BACKUP}"

mapfile -t BASES_BACKUP < <(find "${BACKUP}/var/lib" -type f -name '*.db' -print)
for database in "${BASES_BACKUP[@]}"; do
    comprobar_integridad_sqlite "${PYTHON}" "${database}"
done

if [[ "${ROL}" == "central" ]]; then
    requerir_comando setfacl
    requerir_comando getfacl
    requerir_comando runuser
    if [[ "${NO_INICIAR}" != true ]]; then
        requerir_comando curl
    fi
    id "${USUARIO_API}" >/dev/null 2>&1 || error "no existe el usuario ${USUARIO_API}."
fi

mapfile -t SERVICIOS < <(servicios_del_rol "${ROL}")
for servicio in "${SERVICIOS[@]}"; do
    systemctl cat "${servicio}" >/dev/null 2>&1 || \
        error "no está instalado ${servicio}."
done
detener_servicios "${SERVICIOS[@]}"

limpiar_sidecars_sqlite "${DIRECTORIO_ESTADO}/auditoria.db"
limpiar_sidecars_sqlite "${DIRECTORIO_ESTADO}/notifications.db"
if [[ "${ROL}" == "central" ]]; then
    limpiar_sidecars_sqlite "${DIRECTORIO_AUTH}/auth.db"
    limpiar_sidecars_sqlite "${DIRECTORIO_CENTRAL}/central.db"
fi

install -d -m 0750 "${DIRECTORIO_CONFIG}"
install -d -m 0700 "${DIRECTORIO_ESTADO}"
install -m 0640 -o root -g root \
    "${BACKUP}/etc/auditoria-system/agent.env" \
    "${DIRECTORIO_CONFIG}/agent.env"
install -m 0600 -o root -g root \
    "${BACKUP}/etc/auditoria-system/agent-identity.json" \
    "${DIRECTORIO_CONFIG}/agent-identity.json"
install -m 0600 -o root -g root \
    "${BACKUP}/var/lib/auditoria-system/auditoria.db" \
    "${DIRECTORIO_ESTADO}/auditoria.db"
if [[ -f "${BACKUP}/var/lib/auditoria-system/agent_state.json" ]]; then
    install -m 0600 -o root -g root \
        "${BACKUP}/var/lib/auditoria-system/agent_state.json" \
        "${DIRECTORIO_ESTADO}/agent_state.json"
else
    rm -f -- "${DIRECTORIO_ESTADO}/agent_state.json"
fi

if [[ -f "${BACKUP}/var/lib/auditoria-system/notifications.db" ]]; then
    install -m 0600 -o root -g root \
        "${BACKUP}/var/lib/auditoria-system/notifications.db" \
        "${DIRECTORIO_ESTADO}/notifications.db"
else
    rm -f -- "${DIRECTORIO_ESTADO}/notifications.db"
fi

if [[ "${ROL}" == "central" ]]; then
    install -d -m 0700 -o "${USUARIO_API}" -g "${USUARIO_API}" \
        "${DIRECTORIO_AUTH}" "${DIRECTORIO_CENTRAL}"
    install -m 0600 -o "${USUARIO_API}" -g "${USUARIO_API}" \
        "${BACKUP}/var/lib/auditoria-system-auth/auth.db" \
        "${DIRECTORIO_AUTH}/auth.db"
    install -m 0600 -o "${USUARIO_API}" -g "${USUARIO_API}" \
        "${BACKUP}/var/lib/auditoria-system-central/central.db" \
        "${DIRECTORIO_CENTRAL}/central.db"

    if [[ -f "${DIRECTORIO_ESTADO}/notifications.db" ]]; then
        setfacl -m "u:${USUARIO_API}:--x" "${DIRECTORIO_ESTADO}"
        setfacl -m "u:${USUARIO_API}:r--" \
            "${DIRECTORIO_ESTADO}/notifications.db"
    fi
    if getfacl -cp "${DIRECTORIO_ESTADO}/auditoria.db" | \
        grep -q "^user:${USUARIO_API}:"; then
        setfacl -x "u:${USUARIO_API}" "${DIRECTORIO_ESTADO}/auditoria.db"
    fi
    if runuser -u "${USUARIO_API}" -- test -r \
        "${DIRECTORIO_ESTADO}/auditoria.db"; then
        error "${USUARIO_API} puede leer auditoria.db después del restore."
    fi
    if [[ -f "${DIRECTORIO_ESTADO}/notifications.db" ]]; then
        runuser -u "${USUARIO_API}" -- test -r \
            "${DIRECTORIO_ESTADO}/notifications.db" || \
            error "${USUARIO_API} no puede leer notifications.db."
        if runuser -u "${USUARIO_API}" -- test -w \
            "${DIRECTORIO_ESTADO}/notifications.db"; then
            error "${USUARIO_API} puede escribir notifications.db."
        fi
    fi
fi

comprobar_integridad_sqlite "${PYTHON}" "${DIRECTORIO_ESTADO}/auditoria.db"
if [[ -f "${DIRECTORIO_ESTADO}/notifications.db" ]]; then
    comprobar_integridad_sqlite "${PYTHON}" \
        "${DIRECTORIO_ESTADO}/notifications.db"
fi
if [[ "${ROL}" == "central" ]]; then
    comprobar_integridad_sqlite "${PYTHON}" "${DIRECTORIO_AUTH}/auth.db"
    comprobar_integridad_sqlite "${PYTHON}" "${DIRECTORIO_CENTRAL}/central.db"
fi

if [[ "${NO_INICIAR}" == true ]]; then
    echo "Backup restaurado y validado sin iniciar servicios para role ${ROL}."
else
    mapfile -t INICIAR < <(servicios_para_inicio "${ROL}")
    iniciar_servicios "${INICIAR[@]}"
    comprobar_servicios_activos "${INICIAR[@]}"
    if [[ "${ROL}" == "central" ]]; then
        comprobar_health
    fi
    echo "Backup restaurado y validado correctamente para role ${ROL}."
fi
