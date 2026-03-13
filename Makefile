NGINX_VERSION ?= 1.28.2
NGINX_SRC     ?= /tmp/nginx-$(NGINX_VERSION)
MODULE_DIR    := $(shell pwd)
NGINX_BIN     ?= /usr/local/nginx/sbin/nginx

.PHONY: build test clean download docker-build docker-test

# Download nginx source if not present
download:
	@if [ ! -d "$(NGINX_SRC)" ]; then \
		echo "Downloading nginx $(NGINX_VERSION)..."; \
		wget -q -O /tmp/nginx-$(NGINX_VERSION).tar.gz \
			https://nginx.org/download/nginx-$(NGINX_VERSION).tar.gz; \
		cd /tmp && tar xzf nginx-$(NGINX_VERSION).tar.gz; \
		rm -f /tmp/nginx-$(NGINX_VERSION).tar.gz; \
	fi

# Build dynamic module
build: download
	cd $(NGINX_SRC) && ./configure \
		--with-compat \
		--with-http_ssl_module \
		--with-http_realip_module \
		--add-dynamic-module=$(MODULE_DIR) \
	&& make -j$$(nproc) modules
	@echo ""
	@echo "Module built: $(NGINX_SRC)/objs/ngx_http_htaccess_module.so"

# Build and install nginx + module
install: download
	cd $(NGINX_SRC) && ./configure \
		--with-compat \
		--with-http_ssl_module \
		--with-http_realip_module \
		--add-dynamic-module=$(MODULE_DIR) \
	&& make -j$$(nproc) \
	&& sudo make install
	sudo mkdir -p /usr/local/nginx/modules
	sudo cp $(NGINX_SRC)/objs/ngx_http_htaccess_module.so /usr/local/nginx/modules/
	@echo "Installed nginx + htaccess module"

# Run tests (requires nginx + module installed)
test:
	@chmod +x t/run_tests.sh t/helpers.sh t/*.t.sh 2>/dev/null || true
	NGINX_BIN=$(NGINX_BIN) t/run_tests.sh

# Build and test via Docker
docker-build:
	docker build --build-arg NGINX_VERSION=$(NGINX_VERSION) -t nginx-htaccess-test .

docker-test: docker-build
	docker run --rm nginx-htaccess-test

# Clean build artifacts
clean:
	rm -rf $(NGINX_SRC)
	rm -f *.o *.so
