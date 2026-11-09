#!/bin/bash
# ============================================================================
# nginx-htaccess-module installer
#
# Detects installed nginx, downloads matching source, builds the module,
# installs it, and adds load_module to nginx.conf.
#
# Usage:
#   sudo ./install.sh              # auto-detect nginx version
#   sudo ./install.sh 1.30.6       # force specific version
#   ./install.sh --check           # check if module is installed
#   ./install.sh --uninstall       # remove module
# ============================================================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

MODULE_NAME="ngx_http_htaccess_module"
MODULE_SO="${MODULE_NAME}.so"
MODULE_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR=""
CONF_BACKUP=""

# nginx does not publish .sha256 files, only PGP signatures.  Pin the hashes
# for the versions used by CI, and verify the PGP signature for anything else.
NGINX_SHA256_1_28_0="c6b5c6b086c0df9d3ca3ff5e084c1d0ef909e6038279c71c1c3e985f576ff76a"
NGINX_SHA256_1_28_2="20e5e0f2c917acfb51120eec2fba9a4ba4e1e10fd28465067cc87a7d81a829a3"
# checked against the nginx.org PGP signatures (2026-11-08)
NGINX_SHA256_1_24_0="77a2541637b92a621e3ee76776c8b7b40cf6d707e69ba53a940283e30ff2f55d"
NGINX_SHA256_1_30_6="3cf46f5ed7504d460125866b7bea99fb357f31d887e2e63b35503310e9b8b6c8"
NGINX_SHA256_1_31_8="0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1"

# Common nginx module paths
MODULES_PATHS=(
    "/usr/lib/nginx/modules"
    "/usr/lib64/nginx/modules"
    "/usr/local/nginx/modules"
    "/etc/nginx/modules"
    "/opt/nginx/modules"
)

# Common nginx.conf paths
CONF_PATHS=(
    "/etc/nginx/nginx.conf"
    "/usr/local/nginx/conf/nginx.conf"
    "/opt/nginx/conf/nginx.conf"
)

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC} ${BOLD}$1${NC}"; }

# ============================================================================
# Detect system
# ============================================================================

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        DISTRO_VERSION="$VERSION_ID"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        DISTRO="unknown"
    fi
}

detect_nginx() {
    NGINX_BIN=""
    NGINX_VERSION=""
    NGINX_MODULES_DIR=""
    NGINX_CONF=""
    NGINX_PREFIX=""

    # find nginx binary
    if command -v nginx &>/dev/null; then
        NGINX_BIN="$(command -v nginx)"
    elif [ -x /usr/sbin/nginx ]; then
        NGINX_BIN="/usr/sbin/nginx"
    elif [ -x /usr/local/nginx/sbin/nginx ]; then
        NGINX_BIN="/usr/local/nginx/sbin/nginx"
    fi

    if [ -z "$NGINX_BIN" ]; then
        return 1
    fi

    # get version
    NGINX_VERSION=$($NGINX_BIN -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
    if [ -z "$NGINX_VERSION" ]; then
        return 1
    fi

    # get prefix and modules path from nginx -V
    local nginx_v
    nginx_v=$($NGINX_BIN -V 2>&1)

    NGINX_PREFIX=$(echo "$nginx_v" | grep -oP '(?<=--prefix=)\S+' | head -1)
    NGINX_PREFIX=${NGINX_PREFIX:-/etc/nginx}

    # detect modules directory
    local modules_path
    modules_path=$(echo "$nginx_v" | grep -oP '(?<=--modules-path=)\S+' | head -1)
    if [ -n "$modules_path" ] && [ -d "$modules_path" ]; then
        NGINX_MODULES_DIR="$modules_path"
    else
        for p in "${MODULES_PATHS[@]}"; do
            if [ -d "$p" ]; then
                NGINX_MODULES_DIR="$p"
                break
            fi
        done
    fi

    # detect config
    local conf_path
    conf_path=$(echo "$nginx_v" | grep -oP '(?<=--conf-path=)\S+' | head -1)
    if [ -n "$conf_path" ] && [ -f "$conf_path" ]; then
        NGINX_CONF="$conf_path"
    else
        for p in "${CONF_PATHS[@]}"; do
            if [ -f "$p" ]; then
                NGINX_CONF="$p"
                break
            fi
        done
    fi

    return 0
}

# ============================================================================
# Install build dependencies
# ============================================================================

install_deps() {
    log_step "Installing build dependencies..."

    detect_distro

    case "$DISTRO" in
        ubuntu|debian|linuxmint|pop)
            apt-get update -qq
            apt-get install -y -qq build-essential libpcre3-dev libpcre2-dev \
                zlib1g-dev libssl-dev wget ca-certificates 2>/dev/null
            ;;
        centos|rhel|rocky|almalinux|fedora|ol)
            if command -v dnf &>/dev/null; then
                dnf install -y gcc make pcre-devel pcre2-devel zlib-devel \
                    openssl-devel wget 2>/dev/null
            else
                yum install -y gcc make pcre-devel pcre2-devel zlib-devel \
                    openssl-devel wget 2>/dev/null
            fi
            ;;
        arch|manjaro)
            pacman -S --needed --noconfirm base-devel pcre pcre2 zlib openssl wget
            ;;
        alpine)
            apk add --no-cache build-base pcre-dev pcre2-dev zlib-dev \
                openssl-dev wget linux-headers
            ;;
        *)
            log_warn "Unknown distro '$DISTRO'. Please install manually:"
            log_warn "  gcc, make, pcre-dev, zlib-dev, openssl-dev, wget"
            return 1
            ;;
    esac

    log_info "Dependencies installed."
}

# ============================================================================
# Install nginx from official repo
# ============================================================================

install_nginx() {
    detect_distro

    echo ""
    log_step "Installing nginx from official repository..."
    echo ""

    case "$DISTRO" in
        ubuntu|debian|linuxmint|pop)
            # Add nginx official repo
            apt-get install -y -qq curl gnupg2 ca-certificates lsb-release 2>/dev/null

            if [ ! -f /etc/apt/sources.list.d/nginx.list ]; then
                curl -fsSL https://nginx.org/keys/nginx_signing.key \
                    | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg 2>/dev/null

                echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/mainline/${DISTRO} $(lsb_release -cs) nginx" \
                    > /etc/apt/sources.list.d/nginx.list
            fi

            apt-get update -qq
            apt-get install -y nginx
            ;;

        centos|rhel|rocky|almalinux|ol)
            cat > /etc/yum.repos.d/nginx.repo << 'REPO'
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
REPO
            if command -v dnf &>/dev/null; then
                dnf install -y nginx
            else
                yum install -y nginx
            fi
            ;;

        fedora)
            dnf install -y nginx
            ;;

        arch|manjaro)
            pacman -S --needed --noconfirm nginx
            ;;

        alpine)
            apk add --no-cache nginx
            ;;

        *)
            log_error "Cannot auto-install nginx on '$DISTRO'."
            log_warn "Please install nginx manually, then re-run this script."
            return 1
            ;;
    esac

    log_info "nginx installed."
}

# ============================================================================
# Verify downloaded nginx source
# ============================================================================

verify_nginx_source() {
    local file="$1" version="$2" expected=""

    case "$version" in
        1.28.0) expected="$NGINX_SHA256_1_28_0" ;;
        1.28.2) expected="$NGINX_SHA256_1_28_2" ;;
        1.24.0) expected="$NGINX_SHA256_1_24_0" ;;
        1.30.6) expected="$NGINX_SHA256_1_30_6" ;;
        1.31.8) expected="$NGINX_SHA256_1_31_8" ;;
        *)      expected="${NGINX_SHA256:-}" ;;
    esac

    if [ -n "$expected" ]; then
        if echo "${expected}  ${file}" | sha256sum -c - >/dev/null 2>&1; then
            log_info "Source SHA256 verified."
            return 0
        fi
        log_error "nginx source checksum mismatch for $version."
        return 1
    fi

    if command -v gpg &>/dev/null; then
        local gnupg="${BUILD_DIR}/gnupg"

        mkdir -p "$gnupg"
        chmod 700 "$gnupg"

        log_info "Verifying nginx source PGP signature..."
        if wget -q https://nginx.org/keys/nginx_signing.key \
                -O "${BUILD_DIR}/nginx.key" \
           && GNUPGHOME="$gnupg" gpg --batch --quiet --import \
                "${BUILD_DIR}/nginx.key" 2>/dev/null \
           && wget -q "https://nginx.org/download/nginx-${version}.tar.gz.asc" \
                -O "${BUILD_DIR}/nginx.tar.gz.asc" \
           && GNUPGHOME="$gnupg" gpg --batch --verify \
                "${BUILD_DIR}/nginx.tar.gz.asc" "$file" >/dev/null 2>&1
        then
            log_info "PGP signature verified."
            return 0
        fi
        log_warn "GPG verification failed; refusing to build from this tarball."
        return 1
    fi

    log_error "No checksum available for nginx $version and gpg is not installed."
    log_error "Set NGINX_SHA256=<sha256 of the tarball> and re-run."
    return 1
}


# ============================================================================
# Build module
# ============================================================================

build_module() {
    local version="$1"

    log_step "Building module for nginx $version..."

    BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nginx-htaccess-build.XXXXXX")"
    if [ -z "$BUILD_DIR" ] || [ ! -d "$BUILD_DIR" ]; then
        log_error "Failed to create a private build directory."
        return 1
    fi
    cd "$BUILD_DIR"

    local url="https://nginx.org/download/nginx-${version}.tar.gz"
    log_info "Downloading nginx source: $url"

    if ! wget -q "$url" -O nginx.tar.gz; then
        log_error "Failed to download nginx $version source."
        log_warn "Check version at: https://nginx.org/en/download.html"
        return 1
    fi

    if ! verify_nginx_source "${BUILD_DIR}/nginx.tar.gz" "$version"; then
        return 1
    fi

    tar xzf nginx.tar.gz
    cd "nginx-${version}"

    # Get configure arguments from installed nginx
    local configure_args=""
    if [ -n "$NGINX_BIN" ]; then
        configure_args=$($NGINX_BIN -V 2>&1 | grep "configure arguments:" \
            | sed 's/configure arguments: //' \
            | sed 's/--add-dynamic-module=[^ ]* //g' \
            | sed 's/--add-module=[^ ]* //g')
    fi

    # Build with --with-compat for dynamic module compatibility
    log_info "Configuring..."
    if [ -n "$configure_args" ]; then
        eval ./configure $configure_args \
            --add-dynamic-module="$MODULE_DIR" 2>&1 | tail -3
    else
        ./configure --with-compat \
            --add-dynamic-module="$MODULE_DIR" 2>&1 | tail -3
    fi

    log_info "Compiling module..."
    make -j"$(nproc)" modules 2>&1 | tail -5

    if [ ! -f "objs/${MODULE_SO}" ]; then
        log_error "Build failed - ${MODULE_SO} not found."
        return 1
    fi

    BUILT_MODULE="$BUILD_DIR/nginx-${version}/objs/${MODULE_SO}"
    log_info "Build successful: $BUILT_MODULE"
}

# ============================================================================
# Install module
# ============================================================================

install_module() {
    log_step "Installing module..."

    # Create modules directory if needed
    if [ -z "$NGINX_MODULES_DIR" ]; then
        NGINX_MODULES_DIR="/usr/lib/nginx/modules"
    fi
    mkdir -p "$NGINX_MODULES_DIR"

    # Backup existing module
    if [ -f "${NGINX_MODULES_DIR}/${MODULE_SO}" ]; then
        local backup="${NGINX_MODULES_DIR}/${MODULE_SO}.backup.$(date +%s)"
        cp "${NGINX_MODULES_DIR}/${MODULE_SO}" "$backup"
        log_info "Existing module backed up to: $backup"
    fi

    # Copy module
    cp "$BUILT_MODULE" "${NGINX_MODULES_DIR}/${MODULE_SO}"
    chmod 644 "${NGINX_MODULES_DIR}/${MODULE_SO}"
    log_info "Module installed to: ${NGINX_MODULES_DIR}/${MODULE_SO}"

    # Add load_module to nginx.conf if not present
    if [ -n "$NGINX_CONF" ] && [ -f "$NGINX_CONF" ]; then
        if ! grep -q "$MODULE_SO" "$NGINX_CONF"; then
            log_info "Adding load_module to $NGINX_CONF..."

            CONF_BACKUP="${NGINX_CONF}.htaccess-backup.$(date +%s)"
            cp -a "$NGINX_CONF" "$CONF_BACKUP"
            log_info "nginx.conf backed up to: $CONF_BACKUP"

            local module_path
            # Use relative path if modules dir is standard
            if [[ "$NGINX_MODULES_DIR" == */modules ]]; then
                module_path="modules/${MODULE_SO}"
            else
                module_path="${NGINX_MODULES_DIR}/${MODULE_SO}"
            fi

            # Insert load_module at the top of nginx.conf (before events block)
            sed -i "1i load_module ${module_path};" "$NGINX_CONF"
            log_info "Added: load_module ${module_path};"
        else
            log_info "load_module already present in $NGINX_CONF"
        fi
    fi
}

# ============================================================================
# Verify installation
# ============================================================================

verify_install() {
    log_step "Verifying installation..."

    # Test nginx config
    if ! $NGINX_BIN -t 2>&1; then
        log_error "nginx config test failed!"
        log_warn "Check $NGINX_CONF for errors."
        log_warn "You may need to add 'htaccess on;' to a location block."
        return 1
    fi

    log_info "nginx config test passed."
    echo ""
    echo -e "${GREEN}${BOLD}=============================================="
    echo -e "  Installation complete!"
    echo -e "==============================================${NC}"
    echo ""
    echo -e "  Module: ${BOLD}${NGINX_MODULES_DIR}/${MODULE_SO}${NC}"
    echo -e "  nginx:  ${BOLD}${NGINX_BIN} (${NGINX_VERSION})${NC}"
    echo -e "  Config: ${BOLD}${NGINX_CONF}${NC}"
    echo ""
    echo -e "  ${CYAN}Next steps:${NC}"
    echo "  1. Add to your server block:"
    echo ""
    echo "     location / {"
    echo "         htaccess on;"
    echo "     }"
    echo ""
    echo "  2. Reload nginx:"
    echo "     sudo nginx -s reload"
    echo ""
    echo "  3. Create .htaccess in your document root"
    echo ""
}

# ============================================================================
# Check / Status
# ============================================================================

check_status() {
    echo ""
    echo -e "${BOLD}nginx-htaccess-module status${NC}"
    echo "=============================="

    if ! detect_nginx; then
        echo -e "  nginx:  ${RED}not found${NC}"
        echo ""
        return 1
    fi

    echo -e "  nginx:  ${GREEN}${NGINX_VERSION}${NC} (${NGINX_BIN})"

    # Check if module file exists
    local found=0
    for p in "${MODULES_PATHS[@]}"; do
        if [ -f "$p/$MODULE_SO" ]; then
            echo -e "  module: ${GREEN}installed${NC} ($p/$MODULE_SO)"
            found=1
            break
        fi
    done
    if [ $found -eq 0 ]; then
        echo -e "  module: ${RED}not installed${NC}"
    fi

    # Check if load_module is in config
    if [ -n "$NGINX_CONF" ]; then
        if grep -q "$MODULE_SO" "$NGINX_CONF" 2>/dev/null; then
            echo -e "  config: ${GREEN}loaded${NC} (in $NGINX_CONF)"
        else
            echo -e "  config: ${YELLOW}not loaded${NC} (load_module not in $NGINX_CONF)"
        fi
    fi

    # Check if htaccess is enabled in any location
    local htaccess_on
    htaccess_on=$(grep -r "htaccess on" /etc/nginx/ 2>/dev/null | head -1)
    if [ -n "$htaccess_on" ]; then
        echo -e "  active: ${GREEN}yes${NC}"
    else
        echo -e "  active: ${YELLOW}not configured${NC} (add 'htaccess on;' to a location block)"
    fi

    echo ""
    return 0
}

# ============================================================================
# Uninstall
# ============================================================================

uninstall_module() {
    echo ""
    log_step "Uninstalling nginx-htaccess-module..."

    if [ "$(id -u)" -ne 0 ]; then
        log_error "Please run as root: sudo $0 --uninstall"
        exit 1
    fi

    detect_nginx

    # Remove module file
    for p in "${MODULES_PATHS[@]}"; do
        if [ -f "$p/$MODULE_SO" ]; then
            rm -f "$p/$MODULE_SO"
            rm -f "$p/${MODULE_SO}.backup."* 2>/dev/null
            log_info "Removed: $p/$MODULE_SO"
        fi
    done

    # Remove load_module from config
    if [ -n "$NGINX_CONF" ] && [ -f "$NGINX_CONF" ]; then
        if grep -q "$MODULE_SO" "$NGINX_CONF"; then
            sed -i "/$MODULE_SO/d" "$NGINX_CONF"
            log_info "Removed load_module from $NGINX_CONF"
        fi
    fi

    # Remove htaccess directives from all configs
    if [ -d /etc/nginx ]; then
        local files
        files=$(grep -rl "htaccess" /etc/nginx/ 2>/dev/null || true)
        if [ -n "$files" ]; then
            log_warn "These files still contain 'htaccess' directives:"
            echo "$files" | while read -r f; do
                echo "  $f"
            done
            log_warn "Remove 'htaccess on;' / 'htaccess_filename' manually."
        fi
    fi

    # Test config
    if [ -n "$NGINX_BIN" ]; then
        if $NGINX_BIN -t 2>&1; then
            log_info "nginx config OK. Reload with: sudo nginx -s reload"
        fi
    fi

    log_info "Uninstall complete."
    echo ""
}

# ============================================================================
# Cleanup
# ============================================================================

cleanup() {
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR" 2>/dev/null
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo ""
    echo -e "${BOLD}=============================================="
    echo -e "  nginx-htaccess-module installer"
    echo -e "==============================================${NC}"
    echo ""

    # Check arguments
    case "${1:-}" in
        --check|--status|-c)
            check_status
            exit $?
            ;;
        --uninstall|--remove|-u)
            uninstall_module
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] [NGINX_VERSION]"
            echo ""
            echo "Options:"
            echo "  (no args)      Auto-detect nginx and install module"
            echo "  VERSION        Build for specific nginx version (e.g., 1.30.6)"
            echo "  --check, -c    Check installation status"
            echo "  --uninstall    Remove module"
            echo "  --help, -h     Show this help"
            echo ""
            exit 0
            ;;
    esac

    # Must be root for installation
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Please run as root: sudo $0"
        exit 1
    fi

    # Check platform
    if [ "$(uname)" != "Linux" ]; then
        log_error "This module only supports Linux."
        exit 1
    fi

    # Detect or install nginx
    if detect_nginx; then
        log_info "Found nginx ${NGINX_VERSION} at ${NGINX_BIN}"
    else
        log_warn "nginx is not installed."
        echo ""
        read -rp "Install nginx from official repository? [y/N] " answer
        if [[ "$answer" =~ ^[Yy] ]]; then
            install_deps
            install_nginx
            if ! detect_nginx; then
                log_error "nginx installation failed."
                exit 1
            fi
            log_info "Found nginx ${NGINX_VERSION} at ${NGINX_BIN}"
        else
            log_error "nginx is required. Install it and re-run this script."
            exit 1
        fi
    fi

    # Use provided version or detected version
    local version="${1:-$NGINX_VERSION}"

    if [ -z "$version" ]; then
        log_error "Could not determine nginx version."
        echo "Usage: $0 [VERSION]"
        exit 1
    fi

    # Warn if version mismatch
    if [ -n "$1" ] && [ "$1" != "$NGINX_VERSION" ]; then
        log_warn "Building for nginx $1, but installed version is $NGINX_VERSION"
        read -rp "Continue anyway? [y/N] " answer
        [[ "$answer" =~ ^[Yy] ]] || exit 0
    fi

    # Verify module source exists
    if [ ! -f "$MODULE_DIR/config" ]; then
        log_error "Module source not found at: $MODULE_DIR"
        log_error "Run this script from the module directory."
        exit 1
    fi

    # Build
    install_deps
    build_module "$version" || exit 1

    # Install
    install_module

    # Verify
    if ! verify_install; then
        if [ -n "$CONF_BACKUP" ] && [ -f "$CONF_BACKUP" ]; then
            cp -a "$CONF_BACKUP" "$NGINX_CONF"
            log_warn "Restored nginx.conf from $CONF_BACKUP"
        fi
        exit 1
    fi

    # Cleanup
    cleanup

    echo -e "${GREEN}Done!${NC}"
    echo ""
}

trap cleanup EXIT
main "$@"
