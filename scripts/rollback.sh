#!/usr/bin/env bash

set -euo pipefail
umask 0077

DIRECTORIO_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/lib/operaciones-comunes.sh
. "${DIRECTORIO_SCRIPT}/lib/operaciones-comunes.sh"

ROL=""
BACKUP=""
CODIGO_ANTERIOR=""

mostrar_uso() {
    cat <<'EOF'
Uso:
  sudo ./scripts/rollback.sh --role central --backup /ruta/backup \
    --codigo-anterior /opt/auditoria-system.rollback.TIMESTAMP
  sudo ./scripts/rollback.sh --role agent --backup /ruta/backup \
    --codigo-anterior /opt/auditoria-system.rollback.TIMESTAMP
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
        --codigo-anterior)
            [[ $# -ge 2 ]] || { mostrar_uso >&2; error "--codigo-anterior requiere una ruta."; }
            CODIGO_ANTERIOR="$2"
            shift 2
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
[[ -n "${BACKUP}" ]] || error "debe indicar --backup."
[[ -n "${CODIGO_ANTERIOR}" ]] || error "debe indicar --codigo-anterior."
[[ "${BACKUP}" == /* && "${CODIGO_ANTERIOR}" == /* ]] || \
    error "las rutas deben ser absolutas."
requerir_root
validar_ubuntu
requerir_comando systemctl
requerir_comando mv
requerir_comando mktemp
validar_backup "${ROL}" "${BACKUP}"
[[ -d "${CODIGO_ANTERIOR}" && ! -L "${CODIGO_ANTERIOR}" ]] || \
    error "la ruta de código anterior no es válida."
for requerido in app deploy requirements.txt pyproject.toml; do
    [[ -e "${CODIGO_ANTERIOR}/${requerido}" ]] || \
        error "el código anterior no contiene ${requerido}."
done

OPERACIONES_TEMPORALES="$(mktemp -d /tmp/auditoria-operaciones.XXXXXX)"
cp -a "${DIRECTORIO_SCRIPT}/." "${OPERACIONES_TEMPORALES}/"
SERVICIOS_DEBEN_QUEDAR_DETENIDOS=false
CODIGO_FALLIDO=""
limpiar_operaciones() {
    local estado=$?
    local fallo_parada=false
    local servicio
    if [[ "${estado}" -ne 0 && \
          "${SERVICIOS_DEBEN_QUEDAR_DETENIDOS}" == true ]]; then
        for servicio in "${SERVICIOS[@]}"; do
            if ! systemctl stop "${servicio}"; then
                fallo_parada=true
            fi
        done
        if [[ "${fallo_parada}" == true ]]; then
            echo "Error: no se pudo confirmar la parada de todos los servicios." >&2
        else
            echo "Se volvió a solicitar la parada de los servicios del role." >&2
        fi
        if [[ -n "${CODIGO_FALLIDO}" && -e "${CODIGO_FALLIDO}" ]]; then
            echo "Código fallido conservado en: ${CODIGO_FALLIDO}" >&2
        fi
    fi
    case "${OPERACIONES_TEMPORALES}" in
        /tmp/auditoria-operaciones.*)
            rm -rf -- "${OPERACIONES_TEMPORALES}"
            ;;
    esac
    exit "${estado}"
}
trap limpiar_operaciones EXIT

mapfile -t SERVICIOS < <(servicios_del_rol "${ROL}")
SERVICIOS_DEBEN_QUEDAR_DETENIDOS=true
detener_servicios "${SERVICIOS[@]}"

MARCA_TIEMPO="$(date -u +%Y%m%dT%H%M%SZ)"
CODIGO_FALLIDO="${RAIZ_INSTALACION}.fallido.${MARCA_TIEMPO}"
[[ ! -e "${CODIGO_FALLIDO}" ]] || error "ya existe ${CODIGO_FALLIDO}."
if [[ -e "${RAIZ_INSTALACION}" ]]; then
    mv "${RAIZ_INSTALACION}" "${CODIGO_FALLIDO}"
fi
if ! mv "${CODIGO_ANTERIOR}" "${RAIZ_INSTALACION}"; then
    if [[ -e "${CODIGO_FALLIDO}" ]]; then
        mv "${CODIGO_FALLIDO}" "${RAIZ_INSTALACION}"
    fi
    error "no se pudo recuperar el código anterior."
fi

bash "${OPERACIONES_TEMPORALES}/preparar-instalacion.sh"
bash "${OPERACIONES_TEMPORALES}/restaurar-backup.sh" \
    --role "${ROL}" --backup "${BACKUP}" --no-start
bash "${OPERACIONES_TEMPORALES}/instalar-servicio.sh" --role "${ROL}"

mapfile -t INICIAR < <(servicios_para_inicio "${ROL}")
comprobar_servicios_activos "${INICIAR[@]}"
if [[ "${ROL}" == "central" ]]; then
    requerir_comando curl
    comprobar_health
fi

SERVICIOS_DEBEN_QUEDAR_DETENIDOS=false
trap - EXIT
rm -rf -- "${OPERACIONES_TEMPORALES}"
echo "Rollback completado correctamente."
echo "Código fallido conservado en: ${CODIGO_FALLIDO}"
