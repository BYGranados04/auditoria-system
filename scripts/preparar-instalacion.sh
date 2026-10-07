#!/usr/bin/env bash

set -euo pipefail
umask 0022

DIRECTORIO_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/lib/operaciones-comunes.sh
. "${DIRECTORIO_SCRIPT}/lib/operaciones-comunes.sh"

mostrar_uso() {
    cat <<'EOF'
Uso:
  sudo /opt/auditoria-system/scripts/preparar-instalacion.sh

El código de la versión elegida debe existir previamente en
/opt/auditoria-system. Este script no descarga ni selecciona versiones.
EOF
}

if [[ $# -gt 0 ]]; then
    case "$1" in
        -h|--help)
            mostrar_uso
            exit 0
            ;;
        *)
            mostrar_uso >&2
            error "argumento no reconocido: $1"
            ;;
    esac
fi

requerir_root
validar_ubuntu
requerir_comando python3.12
requerir_comando install

validar_estructura_release "${RAIZ_INSTALACION}"

VERSION_PYTHON="$(python3.12 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
[[ "${VERSION_PYTHON}" == "3.12" ]] || error "se requiere Python 3.12."

VENV="${RAIZ_INSTALACION}/.venv"
TEMPORAL=""
limpiar_temporal() {
    local estado=$?
    if [[ -n "${TEMPORAL}" ]]; then
        case "${TEMPORAL}" in
            "${RAIZ_INSTALACION}"/.venv.tmp.*)
                rm -rf -- "${TEMPORAL}"
                ;;
        esac
    fi
    exit "${estado}"
}
trap limpiar_temporal EXIT

if [[ ! -d "${VENV}" ]]; then
    TEMPORAL="${RAIZ_INSTALACION}/.venv.tmp.$$"
    if ! python3.12 -m venv "${TEMPORAL}"; then
        error "no se pudo crear el entorno virtual; instale python3.12-venv."
    fi
    mv "${TEMPORAL}" "${VENV}"
    TEMPORAL=""
    echo "Entorno virtual creado: ${VENV}"
elif [[ ! -x "${VENV}/bin/python" ]]; then
    error "${VENV} existe pero no contiene un entorno virtual válido."
else
    echo "Entorno virtual existente conservado: ${VENV}"
fi

VERSION_VENV="$("${VENV}/bin/python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
[[ "${VERSION_VENV}" == "3.12" ]] || \
    error "el entorno virtual existente no utiliza Python 3.12."

"${VENV}/bin/python" -m pip --disable-pip-version-check install \
    --no-deps --requirement "${RAIZ_INSTALACION}/requirements.txt"
"${VENV}/bin/python" -m pip check

(
    cd "${RAIZ_INSTALACION}"
    "${VENV}/bin/python" -c \
        'from app.agent.__main__ import cli; from app.api.main import app; import fastapi; import psutil; import pydantic; import uvicorn; assert callable(cli) and app is not None'
    "${VENV}/bin/python" -m app.agent --help >/dev/null
)

[[ -x "${VENV}/bin/uvicorn" ]] || error "uvicorn no quedó instalado correctamente."

trap - EXIT
echo
echo "Entorno reproducible preparado correctamente."
echo "Siguiente paso:"
echo "  sudo ${RAIZ_INSTALACION}/scripts/instalar-servicio.sh --role central"
echo "  o"
echo "  sudo ${RAIZ_INSTALACION}/scripts/instalar-servicio.sh --role agent"
