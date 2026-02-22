#!/usr/bin/env bash

set -euo pipefail

SCRIPT_NAME="netapp-ontap-installer"
DEFAULT_REPO_URL="https://github.com/pvolu-vz/NetApp.git"
DEFAULT_BRANCH="main"
DEFAULT_INSTALL_BASE="/opt/netapp-veza"

REPO_URL="${DEFAULT_REPO_URL}"
BRANCH="${DEFAULT_BRANCH}"
INSTALL_BASE="${DEFAULT_INSTALL_BASE}"
NON_INTERACTIVE="false"
OVERWRITE_ENV="false"

APP_DIR=""
LOG_DIR=""
CONFIG_DIR=""
SCRIPT_LOG_DIR=""
VENV_DIR=""
ENV_FILE=""
INSTALL_LOG=""
RUN_AS_ROOT=""
PKG_MANAGER=""
OS_ID=""
APT_UPDATED="false"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[INFO]${NC} $*"
    if [[ -n "${INSTALL_LOG}" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" >> "${INSTALL_LOG}"
    fi
}

ok() {
    echo -e "${GREEN}[OK]${NC} $*"
    if [[ -n "${INSTALL_LOG}" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK] $*" >> "${INSTALL_LOG}"
    fi
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
    if [[ -n "${INSTALL_LOG}" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" >> "${INSTALL_LOG}"
    fi
}

err() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    if [[ -n "${INSTALL_LOG}" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >> "${INSTALL_LOG}"
    fi
}

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [options]

Options:
  --repo-url URL         Git repository URL (default: ${DEFAULT_REPO_URL})
  --branch NAME          Git branch to clone/update (default: ${DEFAULT_BRANCH})
  --install-dir PATH     Base install directory (default: ${DEFAULT_INSTALL_BASE})
  --non-interactive      Do not prompt for values (expects ONTAP/VEZA env vars)
  --overwrite-env        Overwrite existing .env file if present
  -h, --help             Show this help

Required env vars in --non-interactive mode:
  ONTAP_API_BASE_URL ONTAP_USERNAME ONTAP_PASSWORD VEZA_URL VEZA_API_KEY

Optional env vars in --non-interactive mode:
  DOMAIN_TO_REMOVE DOMAIN_SUFFIX
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --repo-url)
                REPO_URL="$2"
                shift 2
                ;;
            --branch)
                BRANCH="$2"
                shift 2
                ;;
            --install-dir)
                INSTALL_BASE="$2"
                shift 2
                ;;
            --non-interactive)
                NON_INTERACTIVE="true"
                shift
                ;;
            --overwrite-env)
                OVERWRITE_ENV="true"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                err "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

configure_paths() {
    APP_DIR="${INSTALL_BASE}/scripts"
    LOG_DIR="${INSTALL_BASE}/logs"
    CONFIG_DIR="${INSTALL_BASE}/configs"
    SCRIPT_LOG_DIR="${APP_DIR}/logs"
    VENV_DIR="${APP_DIR}/venv"
    ENV_FILE="${APP_DIR}/.env"
    INSTALL_LOG="${LOG_DIR}/install_$(date +%Y%m%d_%H%M%S).log"
}

require_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        err "This installer supports Linux only."
        exit 1
    fi
}

detect_package_manager() {
    if command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
    elif command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
    elif command -v zypper >/dev/null 2>&1; then
        PKG_MANAGER="zypper"
    elif command -v apk >/dev/null 2>&1; then
        PKG_MANAGER="apk"
    else
        PKG_MANAGER="none"
    fi

    if [[ "${PKG_MANAGER}" == "none" ]]; then
        err "No supported package manager found (dnf/yum/apt/zypper/apk)."
        exit 1
    fi

    ok "Detected package manager: ${PKG_MANAGER}"

    if [[ -f /etc/os-release ]]; then
        OS_ID="$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')"
    else
        OS_ID="unknown"
    fi
    ok "Detected distro: ${OS_ID}"
}

ensure_root_command() {
    if [[ "${EUID}" -eq 0 ]]; then
        RUN_AS_ROOT=""
    elif command -v sudo >/dev/null 2>&1; then
        RUN_AS_ROOT="sudo"
    else
        err "Root access is required to install system packages and write to ${INSTALL_BASE}."
        err "Run as root or install sudo first."
        exit 1
    fi
}

run_root() {
    if [[ -n "${RUN_AS_ROOT}" ]]; then
        ${RUN_AS_ROOT} "$@"
    else
        "$@"
    fi
}

setup_directories() {
    run_root mkdir -p "${APP_DIR}" "${LOG_DIR}" "${CONFIG_DIR}" "${SCRIPT_LOG_DIR}"
    run_root chmod 755 "${INSTALL_BASE}" "${APP_DIR}" "${LOG_DIR}" "${CONFIG_DIR}" "${SCRIPT_LOG_DIR}"
    run_root touch "${INSTALL_LOG}"
    if [[ "${EUID}" -ne 0 ]]; then
        run_root chown -R "${USER}":"${USER}" "${INSTALL_BASE}"
        run_root chown "${USER}":"${USER}" "${INSTALL_LOG}"
    fi
}

install_system_packages() {
    install_pkg() {
        local pkg="$1"
        case "${PKG_MANAGER}" in
            dnf)
                run_root dnf install -y "${pkg}" >/dev/null
                ;;
            yum)
                run_root yum install -y "${pkg}" >/dev/null
                ;;
            apt)
                if [[ "${APT_UPDATED}" != "true" ]]; then
                    run_root apt-get update -y >/dev/null
                    APT_UPDATED="true"
                fi
                run_root apt-get install -y "${pkg}" >/dev/null
                ;;
            zypper)
                run_root zypper --non-interactive install "${pkg}" >/dev/null
                ;;
            apk)
                run_root apk add --no-cache "${pkg}" >/dev/null
                ;;
        esac
    }

    if ! command -v git >/dev/null 2>&1; then
        log "Installing git..."
        install_pkg "git"
    fi

    if ! command -v curl >/dev/null 2>&1; then
        if command -v wget >/dev/null 2>&1; then
            warn "curl not found, but wget is available. Continuing without installing curl."
        elif [[ "${OS_ID}" == "amzn" ]]; then
            warn "curl not found on Amazon Linux; skipping curl install to avoid curl-minimal conflicts."
            warn "Install curl-minimal manually if needed: sudo dnf install -y curl-minimal"
        else
            log "Installing curl..."
            install_pkg "curl"
        fi
    else
        ok "curl already present; skipping curl package install"
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        log "Installing python3..."
        install_pkg "python3"
    fi

    if ! python3 -m pip --version >/dev/null 2>&1; then
        log "Installing python3 pip..."
        case "${PKG_MANAGER}" in
            apk)
                install_pkg "py3-pip"
                ;;
            *)
                install_pkg "python3-pip"
                ;;
        esac
    fi

    if ! python3 -m venv --help >/dev/null 2>&1; then
        warn "python3 venv module not available; installing venv support..."
        case "${PKG_MANAGER}" in
            dnf)
                run_root dnf install -y python3-virtualenv >/dev/null
                ;;
            yum)
                run_root yum install -y python3-virtualenv >/dev/null
                ;;
            apt)
                run_root apt-get install -y python3-venv >/dev/null
                ;;
            zypper)
                run_root zypper --non-interactive install python3-virtualenv >/dev/null
                ;;
            apk)
                run_root apk add --no-cache py3-virtualenv >/dev/null
                ;;
        esac
    fi

    ok "System packages verified"
}

sync_repository() {
    if [[ -d "${APP_DIR}/.git" ]]; then
        log "Existing repository found in ${APP_DIR}; updating from ${REPO_URL} (${BRANCH})"
        git -C "${APP_DIR}" remote set-url origin "${REPO_URL}" >> "${INSTALL_LOG}" 2>&1
        git -C "${APP_DIR}" fetch --all --prune >> "${INSTALL_LOG}" 2>&1
        git -C "${APP_DIR}" checkout "${BRANCH}" >> "${INSTALL_LOG}" 2>&1
        git -C "${APP_DIR}" pull --ff-only origin "${BRANCH}" >> "${INSTALL_LOG}" 2>&1
    else
        if [[ -n "$(ls -A "${APP_DIR}" 2>/dev/null)" ]]; then
            warn "${APP_DIR} is not empty. Existing files may be overwritten by git clone."
            run_root rm -rf "${APP_DIR}"
            run_root mkdir -p "${APP_DIR}"
            if [[ "${EUID}" -ne 0 ]]; then
                run_root chown "${USER}":"${USER}" "${APP_DIR}"
            fi
        fi

        log "Cloning repository ${REPO_URL} (${BRANCH}) into ${APP_DIR}"
        git clone --branch "${BRANCH}" --single-branch "${REPO_URL}" "${APP_DIR}" >> "${INSTALL_LOG}" 2>&1
    fi

    # Ensure all scripts are executable after clone/update
    chmod +x "${APP_DIR}/netAppShares.py" 2>/dev/null || true
    chmod +x "${APP_DIR}/preflight.sh"    2>/dev/null || true
    chmod +x "${APP_DIR}/run_multi_ontap_sync.sh" 2>/dev/null || true
    ok "File permissions set"

    ok "Repository synchronized"
}

setup_python_environment() {
    log "Creating/updating Python virtual environment"
    if [[ ! -d "${VENV_DIR}" ]]; then
        python3 -m venv "${VENV_DIR}"
    fi
    ok "Virtual environment ready: ${VENV_DIR}"

    log "Upgrading pip inside virtual environment..."
    "${VENV_DIR}/bin/python" -m pip install --upgrade pip 2>&1 | tee -a "${INSTALL_LOG}" | tail -1

    log "Installing Python dependencies from requirements.txt..."
    if ! "${VENV_DIR}/bin/pip" install -r "${APP_DIR}/requirements.txt" 2>&1 | tee -a "${INSTALL_LOG}"; then
        err "pip install failed. Check ${INSTALL_LOG} for details."
        exit 1
    fi

    # Verify each package can be imported; uses "distname:importname" pairs
    # because python-dotenv installs as "dotenv" module but the dist is "python-dotenv"
    log "Verifying installed packages..."
    local failed=0
    local pkg_map=(
        "requests:requests"
        "python-dotenv:dotenv"
        "oaaclient:oaaclient"
    )
    for entry in "${pkg_map[@]}"; do
        local dist_name="${entry%%:*}"
        local import_name="${entry##*:}"
        if "${VENV_DIR}/bin/python" -c "import ${import_name}" 2>/dev/null; then
            local ver
            ver=$("${VENV_DIR}/bin/pip" show "${dist_name}" 2>/dev/null | grep '^Version:' | awk '{print $2}')
            ok "${dist_name} ${ver:-installed} verified in venv"
        else
            err "${dist_name} (import: ${import_name}) failed to import after install"
            failed=$((failed + 1))
        fi
    done

    if [[ ${failed} -gt 0 ]]; then
        err "${failed} package(s) failed to import. Run: ${VENV_DIR}/bin/pip install -r ${APP_DIR}/requirements.txt"
        exit 1
    fi

    ok "All Python dependencies installed and verified"
}

prompt_value() {
    local prompt_text="$1"
    local default_value="$2"
    local required="$3"
    local secret="$4"
    local value=""

    # All prompts and warnings must go to /dev/tty so they are visible when
    # the script is piped via "curl | bash" (stdin is the pipe, not the terminal)
    # and so that warn/echo output is NOT captured by the $(...) substitution.
    while true; do
        if [[ "${secret}" == "true" ]]; then
            if [[ -n "${default_value}" ]]; then
                IFS= read -r -s -p "${prompt_text} [current kept if empty]: " value </dev/tty
            else
                IFS= read -r -s -p "${prompt_text}: " value </dev/tty
            fi
            echo >/dev/tty  # newline after silent input - goes to tty, not captured
        else
            if [[ -n "${default_value}" ]]; then
                IFS= read -r -p "${prompt_text} [${default_value}]: " value </dev/tty
            else
                IFS= read -r -p "${prompt_text}: " value </dev/tty
            fi
        fi

        if [[ -z "${value}" && -n "${default_value}" ]]; then
            value="${default_value}"
        fi

        if [[ "${required}" == "true" && -z "${value}" ]]; then
            echo -e "${YELLOW}[WARN]${NC} This value is required." >/dev/tty
            continue
        fi

        echo "${value}"  # only this goes to stdout -> captured by $(...)
        return 0
    done
}

sanitize_veza_url() {
    local raw="$1"
    raw="${raw#https://}"
    raw="${raw#http://}"
    raw="${raw%/}"
    echo "${raw}"
}

load_existing_env_defaults() {
    EXISTING_ONTAP_API_BASE_URL=""
    EXISTING_ONTAP_USERNAME=""
    EXISTING_VEZA_URL=""
    EXISTING_DOMAIN_TO_REMOVE=""
    EXISTING_DOMAIN_SUFFIX=""

    if [[ -f "${ENV_FILE}" ]]; then
        EXISTING_ONTAP_API_BASE_URL="$(grep -E '^ONTAP_API_BASE_URL=' "${ENV_FILE}" | tail -1 | cut -d'=' -f2- || true)"
        EXISTING_ONTAP_USERNAME="$(grep -E '^ONTAP_USERNAME=' "${ENV_FILE}" | tail -1 | cut -d'=' -f2- || true)"
        EXISTING_VEZA_URL="$(grep -E '^VEZA_URL=' "${ENV_FILE}" | tail -1 | cut -d'=' -f2- || true)"
        EXISTING_DOMAIN_TO_REMOVE="$(grep -E '^DOMAIN_TO_REMOVE=' "${ENV_FILE}" | tail -1 | cut -d'=' -f2- || true)"
        EXISTING_DOMAIN_SUFFIX="$(grep -E '^DOMAIN_SUFFIX=' "${ENV_FILE}" | tail -1 | cut -d'=' -f2- || true)"
    fi
}

create_env_file() {
    if [[ -f "${ENV_FILE}" && "${OVERWRITE_ENV}" != "true" ]]; then
        warn "${ENV_FILE} already exists. Reusing existing file (use --overwrite-env to regenerate)."
        return 0
    fi

    load_existing_env_defaults

    local ontap_api_base_url=""
    local ontap_username=""
    local ontap_password=""
    local veza_url=""
    local veza_api_key=""
    local domain_to_remove=""
    local domain_suffix=""

    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        ontap_api_base_url="${ONTAP_API_BASE_URL:-}"
        ontap_username="${ONTAP_USERNAME:-}"
        ontap_password="${ONTAP_PASSWORD:-}"
        veza_url="${VEZA_URL:-}"
        veza_api_key="${VEZA_API_KEY:-}"
        domain_to_remove="${DOMAIN_TO_REMOVE:-}"
        domain_suffix="${DOMAIN_SUFFIX:-}"

        if [[ -z "${ontap_api_base_url}" || -z "${ontap_username}" || -z "${ontap_password}" || -z "${veza_url}" || -z "${veza_api_key}" ]]; then
            err "Missing required environment variables for --non-interactive mode."
            exit 1
        fi
    else
        log "Collecting ONTAP + Veza configuration for .env"
        ontap_api_base_url="$(prompt_value "ONTAP API base URL (example: https://ontap-mgmt.example.com)" "${EXISTING_ONTAP_API_BASE_URL}" "true" "false")"
        ontap_username="$(prompt_value "ONTAP username" "${EXISTING_ONTAP_USERNAME}" "true" "false")"
        ontap_password="$(prompt_value "ONTAP password" "" "true" "true")"
        veza_url="$(prompt_value "Veza URL (example: your-company.veza.com)" "${EXISTING_VEZA_URL}" "true" "false")"
        veza_api_key="$(prompt_value "Veza API key" "" "true" "true")"
        domain_to_remove="$(prompt_value "Domain prefix to remove (optional, example: RTI)" "${EXISTING_DOMAIN_TO_REMOVE}" "false" "false")"
        domain_suffix="$(prompt_value "Domain suffix (optional, example: rti.org)" "${EXISTING_DOMAIN_SUFFIX}" "false" "false")"
    fi

    veza_url="$(sanitize_veza_url "${veza_url}")"

    cat > "${ENV_FILE}" <<EOF
# NetApp ONTAP Configuration
ONTAP_API_BASE_URL=${ontap_api_base_url}
ONTAP_USERNAME=${ontap_username}
ONTAP_PASSWORD=${ontap_password}

# Veza Configuration
VEZA_URL=${veza_url}
VEZA_API_KEY=${veza_api_key}

# Optional identity normalization
DOMAIN_TO_REMOVE=${domain_to_remove}
DOMAIN_SUFFIX=${domain_suffix}
EOF

chmod 600 "${ENV_FILE}"
ok ".env created at ${ENV_FILE}"
}

check_python_version() {
    local version
    version="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    local major minor
    major="${version%%.*}"
    minor="${version##*.}"
    if (( major < 3 || (major == 3 && minor < 7) )); then
        err "Python ${version} detected; Python 3.7+ required."
        exit 1
    fi
    ok "Python ${version} is supported"
}

check_required_files() {
    local required_files=(
        "${APP_DIR}/netAppShares.py"
        "${APP_DIR}/preflight.sh"
        "${APP_DIR}/requirements.txt"
    )

    for f in "${required_files[@]}"; do
        if [[ ! -f "${f}" ]]; then
            err "Required file missing: ${f}"
            exit 1
        fi
    done
    ok "Core files present"
}

check_python_imports() {
    local failed=0
    for pkg in requests dotenv oaaclient; do
        if "${VENV_DIR}/bin/python" -c "import ${pkg}" 2>/dev/null; then
            ok "${pkg} importable in venv"
        else
            err "${pkg} NOT importable in venv"
            failed=$((failed + 1))
        fi
    done
    if [[ ${failed} -gt 0 ]]; then
        err "Run manually to fix: ${VENV_DIR}/bin/pip install -r ${APP_DIR}/requirements.txt"
        exit 1
    fi
    ok "All dependency imports validated"
}

test_connectivity() {
    local target="$1"
    local endpoint="$2"

    if [[ -z "${endpoint}" ]]; then
        warn "Skipping ${target} connectivity test (empty host)"
        return 0
    fi

    local url="${endpoint}"
    if [[ ! "${url}" =~ ^https?:// ]]; then
        url="https://${url}"
    fi

    if curl -k -sS --connect-timeout 8 --max-time 15 "${url}" >/dev/null; then
        ok "Connectivity check passed: ${target} (${url})"
    else
        warn "Connectivity check failed: ${target} (${url})"
    fi
}

run_post_install_checks() {
    log "Running post-install checks (preflight-style)"
    check_python_version
    check_required_files
    check_python_imports

    local ontap_url veza_url
    ontap_url="$(grep -E '^ONTAP_API_BASE_URL=' "${ENV_FILE}" | cut -d'=' -f2-)"
    veza_url="$(grep -E '^VEZA_URL=' "${ENV_FILE}" | cut -d'=' -f2-)"

    test_connectivity "ONTAP API" "${ontap_url}"
    test_connectivity "Veza API" "${veza_url}"

    ok "Post-install checks completed"
}

print_summary() {
    cat <<EOF

Installation complete.

Paths:
  Base:      ${INSTALL_BASE}
  Scripts:   ${APP_DIR}
  Venv:      ${VENV_DIR}
  Config:    ${ENV_FILE}
  Logs:      ${LOG_DIR}
  Log file:  ${INSTALL_LOG}

Run the integration:
  ${VENV_DIR}/bin/python ${APP_DIR}/netAppShares.py --system-type ontap --svm-name YOUR_SVM --protocol cifs --env-file ${ENV_FILE}

Validate prerequisites:
  cd ${APP_DIR} && bash preflight.sh
EOF
}

main() {
    parse_args "$@"
    require_linux
    detect_package_manager
    ensure_root_command
    configure_paths
    setup_directories

    log "Starting ONTAP installer"
    log "Repository: ${REPO_URL} (${BRANCH})"
    log "Install base: ${INSTALL_BASE}"

    install_system_packages
    sync_repository
    setup_python_environment
    create_env_file
    run_post_install_checks
    print_summary
}

main "$@"
