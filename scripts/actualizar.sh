#!/usr/bin/env bash

set -euo pipefail
umask 0077

DIRECTORIO_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/lib/operaciones-comunes.sh
. "${DIRECTORIO_SCRIPT}/lib/operaciones-comunes.sh"

ROL=""
FUENTE=""
DESTINO_BACKUP="/var/backups/auditoria-system"

mostrar_uso() {
    cat <<'EOF'
Uso:
  sudo ./scripts/actualizar.sh --role central --source /ruta/release
  sudo ./scripts/actualizar.sh --role agent --source /ruta/release

Opcional:
  --destino-backup /ruta

La fuente debe contener una versión preparada explícitamente. Este script no
ejecuta git pull, git reset ni descarga código.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)
            [[ $# -ge 2 ]] || { mostrar_uso >&2; error "--role requiere un valor."; }
            ROL="$2"
            shift 2
            ;;
        --source)
            [[ $# -ge 2 ]] || { mostrar_uso >&2; error "--source requiere una ruta."; }
            FUENTE="$2"
            shift 2
            ;;
        --destino-backup)
            [[ $# -ge 2 ]] || { mostrar_uso >&2; error "--destino-backup requiere una ruta."; }
            DESTINO_BACKUP="$2"
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
[[ -n "${FUENTE}" ]] || error "debe indicar --source."
[[ "${FUENTE}" == /* && "${DESTINO_BACKUP}" == /* ]] || \
    error "las rutas deben ser absolutas."
requerir_root
validar_ubuntu
requerir_comando tar
requerir_comando systemctl
requerir_comando readlink
[[ -d "${RAIZ_INSTALACION}" && ! -L "${RAIZ_INSTALACION}" ]] || \
    error "no existe una instalación válida en ${RAIZ_INSTALACION}."
[[ -d "${FUENTE}" && ! -L "${FUENTE}" ]] || error "--source no es válido."
validar_destino_fuera_instalacion "${DESTINO_BACKUP}"

FUENTE_REAL="$(readlink -f "${FUENTE}")"
RAIZ_REAL="$(readlink -f "${RAIZ_INSTALACION}")"
RELEASE_OPERACIONES="$(readlink -f "${DIRECTORIO_SCRIPT}/..")"
[[ "${FUENTE_REAL}" != "${RAIZ_REAL}" && \
   "${FUENTE_REAL}" != "${RAIZ_REAL}"/* ]] || \
    error "--source debe estar fuera de la instalación activa."
[[ "${FUENTE_REAL}" == "${RELEASE_OPERACIONES}" ]] || \
    error "ejecute actualizar.sh desde la misma release indicada en --source."

validar_estructura_release "${FUENTE_REAL}"

SALIDA_BACKUP="$(bash "${DIRECTORIO_SCRIPT}/backup.sh" \
    --role "${ROL}" --destino "${DESTINO_BACKUP}")"
echo "${SALIDA_BACKUP}"
BACKUP="$(printf '%s\n' "${SALIDA_BACKUP}" | \
    sed -n 's/^BACKUP_CREADO=//p' | tail -n 1)"
[[ -n "${BACKUP}" && -d "${BACKUP}" ]] || error "no se obtuvo un backup válido."

mapfile -t SERVICIOS < <(servicios_del_rol "${ROL}")
mapfile -t ACTIVOS_ANTES < <(servicios_activos "${SERVICIOS[@]}")
detener_servicios "${SERVICIOS[@]}"

MARCA_TIEMPO="$(date -u +%Y%m%dT%H%M%SZ)"
CODIGO_ANTERIOR="${RAIZ_INSTALACION}.rollback.${MARCA_TIEMPO}"
[[ ! -e "${CODIGO_ANTERIOR}" ]] || error "ya existe ${CODIGO_ANTERIOR}."
if ! mv "${RAIZ_INSTALACION}" "${CODIGO_ANTERIOR}"; then
    if [[ ${#ACTIVOS_ANTES[@]} -gt 0 ]]; then
        iniciar_servicios "${ACTIVOS_ANTES[@]}"
    fi
    error "no se pudo conservar el código anterior."
fi

ROLLBACK_NECESARIO=true
revertir_si_falla() {
    local estado=$?
    if [[ "${ROLLBACK_NECESARIO}" == true ]]; then
        echo "La actualización falló; iniciando rollback automático." >&2
        bash "${DIRECTORIO_SCRIPT}/rollback.sh" \
            --role "${ROL}" --backup "${BACKUP}" \
            --codigo-anterior "${CODIGO_ANTERIOR}" || \
            echo "Error: el rollback automático también falló." >&2
    fi
    exit "${estado}"
}
trap revertir_si_falla EXIT

copiar_codigo_release "${FUENTE}" "${RAIZ_INSTALACION}"
bash "${RAIZ_INSTALACION}/scripts/preparar-instalacion.sh"
bash "${RAIZ_INSTALACION}/scripts/instalar-servicio.sh" --role "${ROL}"

mapfile -t INICIAR < <(servicios_para_inicio "${ROL}")
comprobar_servicios_activos "${INICIAR[@]}"
if [[ "${ROL}" == "central" ]]; then
    requerir_comando curl
    comprobar_health
fi

ROLLBACK_NECESARIO=false
trap - EXIT
echo "Actualización completada correctamente."
echo "Backup previo: ${BACKUP}"
echo "Código anterior: ${CODIGO_ANTERIOR}"
echo "Rollback manual:"
echo "  sudo bash ${DIRECTORIO_SCRIPT}/rollback.sh --role ${ROL} --backup ${BACKUP} --codigo-anterior ${CODIGO_ANTERIOR}"
