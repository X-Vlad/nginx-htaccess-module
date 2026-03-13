#!/bin/bash
# nginx-htaccess-module Demo Manager
# Usage: ./demo.sh

cd "$(dirname "$0")"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

show_menu() {
    clear
    echo -e "${BOLD}=============================================="
    echo -e "  nginx-htaccess-module Demo Manager"
    echo -e "==============================================${NC}"
    echo ""
    echo -e "  ${CYAN}--- Simple Demo (PHP-FPM) ---${NC}"
    echo "   1. Build + Start"
    echo "   2. Rebuild (no cache) + Start"
    echo "   3. Stop"
    echo "   4. Logs (follow)"
    echo "   5. Logs (last 50 lines)"
    echo ""
    echo -e "  ${CYAN}--- WordPress Demo (PHP-FPM + MySQL) ---${NC}"
    echo "   6. Build + Start"
    echo "   7. Rebuild (no cache) + Start"
    echo "   8. Stop"
    echo "   9. Logs (follow)"
    echo "  10. Logs (last 50 lines)"
    echo ""
    echo -e "  ${CYAN}--- Native Build (no Docker) ---${NC}"
    echo "  11. Build module (.so)"
    echo "  12. Build + Run tests"
    echo ""
    echo -e "  ${CYAN}--- Utils ---${NC}"
    echo "  13. Shell into nginx container"
    echo "  14. Shell into php container"
    echo "  15. Stop ALL containers"
    echo "  16. Run unit tests (Docker)"
    echo ""
    echo "   0. Exit"
    echo ""
    echo -e "${BOLD}==============================================${NC}"
}

wait_key() {
    echo ""
    read -rp "Press Enter to continue..."
}

# Detect docker compose command
if docker compose version &>/dev/null; then
    DC="docker compose"
elif command -v docker-compose &>/dev/null; then
    DC="docker-compose"
else
    DC=""
fi

# Detect system nginx source for native build
detect_nginx_src() {
    if [ -n "$NGINX_SRC" ] && [ -d "$NGINX_SRC" ]; then
        return 0
    fi
    # common locations
    for d in /usr/src/nginx /opt/nginx-src /tmp/nginx-*; do
        if [ -d "$d" ] && [ -f "$d/configure" ]; then
            NGINX_SRC="$d"
            return 0
        fi
    done
    return 1
}

native_build() {
    local MODULE_DIR
    MODULE_DIR="$(cd .. && pwd)"

    if ! detect_nginx_src; then
        echo -e "${YELLOW}nginx source not found. Downloading...${NC}"
        local NGINX_VERSION
        if command -v nginx &>/dev/null; then
            NGINX_VERSION=$(nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
        fi
        NGINX_VERSION=${NGINX_VERSION:-1.28.2}
        echo "Using nginx version: $NGINX_VERSION"

        NGINX_SRC="/tmp/nginx-${NGINX_VERSION}"
        if [ ! -d "$NGINX_SRC" ]; then
            wget -q "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -O /tmp/nginx.tar.gz \
                || { echo -e "${RED}Failed to download nginx source${NC}"; return 1; }
            tar xzf /tmp/nginx.tar.gz -C /tmp
            rm -f /tmp/nginx.tar.gz
        fi
    fi

    echo -e "${GREEN}Building module from: ${MODULE_DIR}${NC}"
    echo -e "${GREEN}Using nginx source: ${NGINX_SRC}${NC}"
    echo ""

    cd "$NGINX_SRC" || return 1
    ./configure --with-compat --add-dynamic-module="$MODULE_DIR" \
        2>&1 | tail -5
    echo ""
    make -j"$(nproc)" modules 2>&1
    local rc=$?

    if [ $rc -eq 0 ]; then
        echo ""
        echo -e "${GREEN}Build successful!${NC}"
        echo -e "Module: ${BOLD}${NGINX_SRC}/objs/ngx_http_htaccess_module.so${NC}"
        echo ""
        echo "To install:"
        echo "  sudo cp objs/ngx_http_htaccess_module.so /usr/lib/nginx/modules/"
        echo "  # Add to nginx.conf: load_module modules/ngx_http_htaccess_module.so;"
    else
        echo -e "${RED}Build failed!${NC}"
    fi
    cd - >/dev/null
    return $rc
}

native_test() {
    native_build || return 1
    echo ""
    echo -e "${CYAN}Running tests...${NC}"
    echo ""
    local TEST_DIR
    TEST_DIR="$(cd ../t && pwd)"
    if [ -f "$TEST_DIR/run_tests.sh" ]; then
        bash "$TEST_DIR/run_tests.sh"
    else
        echo -e "${YELLOW}Tests not found at ${TEST_DIR}/run_tests.sh${NC}"
    fi
}

while true; do
    show_menu
    read -rp "Select: " choice

    case "$choice" in
        1)
            echo ""
            echo -e "${GREEN}Building and starting Simple Demo...${NC}"
            $DC -f docker-compose.yml build
            $DC -f docker-compose.yml up -d
            echo ""
            echo -e "${GREEN}Demo available at: ${BOLD}http://localhost:8080${NC}"
            wait_key
            ;;
        2)
            echo ""
            echo -e "${GREEN}Rebuilding (no cache) and starting Simple Demo...${NC}"
            $DC -f docker-compose.yml down
            $DC -f docker-compose.yml build --no-cache
            $DC -f docker-compose.yml up -d
            echo ""
            echo -e "${GREEN}Demo available at: ${BOLD}http://localhost:8080${NC}"
            wait_key
            ;;
        3)
            echo ""
            $DC -f docker-compose.yml down
            echo -e "${GREEN}Simple Demo stopped.${NC}"
            wait_key
            ;;
        4)
            echo ""
            echo -e "${YELLOW}Press Ctrl+C to stop following logs...${NC}"
            $DC -f docker-compose.yml logs -f
            wait_key
            ;;
        5)
            echo ""
            $DC -f docker-compose.yml logs --tail=50
            wait_key
            ;;
        6)
            echo ""
            echo -e "${GREEN}Building and starting WordPress Demo...${NC}"
            $DC -f docker-compose.wordpress.yml build
            $DC -f docker-compose.wordpress.yml up -d
            echo ""
            echo -e "${GREEN}WordPress available at: ${BOLD}http://localhost:8080${NC}"
            echo -e "MySQL: host=mysql db=wordpress user=wp pass=wppass"
            wait_key
            ;;
        7)
            echo ""
            echo -e "${GREEN}Rebuilding (no cache) and starting WordPress Demo...${NC}"
            $DC -f docker-compose.wordpress.yml down
            $DC -f docker-compose.wordpress.yml build --no-cache
            $DC -f docker-compose.wordpress.yml up -d
            echo ""
            echo -e "${GREEN}WordPress available at: ${BOLD}http://localhost:8080${NC}"
            echo -e "MySQL: host=mysql db=wordpress user=wp pass=wppass"
            wait_key
            ;;
        8)
            echo ""
            $DC -f docker-compose.wordpress.yml down
            echo -e "${GREEN}WordPress Demo stopped.${NC}"
            wait_key
            ;;
        9)
            echo ""
            echo -e "${YELLOW}Press Ctrl+C to stop following logs...${NC}"
            $DC -f docker-compose.wordpress.yml logs -f
            wait_key
            ;;
        10)
            echo ""
            $DC -f docker-compose.wordpress.yml logs --tail=50
            wait_key
            ;;
        11)
            echo ""
            native_build
            wait_key
            ;;
        12)
            echo ""
            native_test
            wait_key
            ;;
        13)
            echo ""
            echo "Connecting to nginx container... (type 'exit' to return)"
            $DC -f docker-compose.yml exec nginx bash 2>/dev/null \
                || $DC -f docker-compose.wordpress.yml exec nginx bash
            wait_key
            ;;
        14)
            echo ""
            echo "Connecting to PHP container... (type 'exit' to return)"
            $DC -f docker-compose.yml exec php bash 2>/dev/null \
                || $DC -f docker-compose.wordpress.yml exec php bash
            wait_key
            ;;
        15)
            echo ""
            echo "Stopping all demo containers..."
            $DC -f docker-compose.yml down 2>/dev/null
            $DC -f docker-compose.wordpress.yml down 2>/dev/null
            echo -e "${GREEN}All stopped.${NC}"
            wait_key
            ;;
        16)
            echo ""
            echo -e "${GREEN}Building and running unit tests (Docker)...${NC}"
            docker build -t htaccess-test -f ../Dockerfile ..
            docker run --rm htaccess-test bash /tests/run_tests.sh
            wait_key
            ;;
        0)
            echo "Bye!"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            sleep 1
            ;;
    esac
done
