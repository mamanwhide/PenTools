# ─────────────────────────────────────────────────────────────────────────
# Pentest Tools Container
# Alpine Linux + all Phase 1 pentest binaries
# Outputs binaries to /opt/tools/bin (shared Docker volume)
# ─────────────────────────────────────────────────────────────────────────
FROM alpine:3.20 AS base

RUN apk add --no-cache \
    bash curl wget git python3 py3-pip ruby ruby-dev \
    nmap nmap-scripts masscan \
    openssl libssl3 ca-certificates \
    build-base libffi-dev \
    libpcap-dev \
    libxml2-dev libxslt-dev \
    c-ares-dev \
    nodejs npm \
    exiftool \
    && rm -rf /var/cache/apk/*

# ── Go Tools Builder ──────────────────────────────────────────────────────
# Use the official Go Alpine image so we always have a recent Go toolchain
# (katana v1.5+ and trufflehog v3 require Go >= 1.25; golang:alpine ships latest).
# GOTOOLCHAIN=auto lets the go command auto-download any even-newer toolchain
# if a specific module requires it.
FROM golang:alpine AS go-builder

RUN apk add --no-cache \
    bash build-base git libpcap-dev ca-certificates \
    && rm -rf /var/cache/apk/*

ENV GOBIN=/opt/tools/bin
ENV GOTOOLCHAIN=auto
# CGO_ENABLED=0 → fully static binaries; no libc dependency.
# Compatible with both Alpine (musl) and Debian (glibc) containers.
ENV CGO_ENABLED=0

RUN mkdir -p /opt/tools/bin /opt/tools/lib

# Each RUN is a separate layer so a single tool failure doesn't block others.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
# katana requires CGO (uses go-tree-sitter C library for JS parsing)
RUN git clone --depth=1 https://github.com/projectdiscovery/katana.git /tmp/katana && \
    cd /tmp/katana/cmd/katana && CGO_ENABLED=1 go build -o /opt/tools/bin/katana . && \
    rm -rf /tmp/katana || true
RUN go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>/dev/null || true
RUN go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || true
RUN go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true
RUN go install github.com/sensepost/gowitness@latest 2>/dev/null || true
# trufflehog: go install fails due to replace directives; use git clone + go build
RUN git clone --depth=1 https://github.com/trufflesecurity/trufflehog.git /tmp/trufflehog && \
    cd /tmp/trufflehog && go build -o /opt/tools/bin/trufflehog . && \
    rm -rf /tmp/trufflehog || true
RUN go install github.com/OJ/gobuster/v3@latest 2>/dev/null || true
RUN go install github.com/ferreiraklet/airixss@latest 2>/dev/null || true

# ── NEW HIGH-VALUE TOOLS ──────────────────────────────────────────────────────
# amass v4: OSINT subdomain enumeration. Use explicit cmd path — v4/...@latest
# can fail with replace directives. Build via git clone as fallback.
RUN go install github.com/owasp-amass/amass/v4/cmd/amass@latest 2>/dev/null || \
    (git clone --depth=1 --branch v4.2.0 https://github.com/owasp-amass/amass.git /tmp/amass \
     && cd /tmp/amass && go build -o /opt/tools/bin/amass ./cmd/amass/ \
     && rm -rf /tmp/amass) || true
# waybackurls: fetch known URLs from Wayback Machine
RUN go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || true
# gau (Get All URLs): Wayback, OTX, Common Crawl, URLScan
RUN go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true
# tlsx: fast TLS/SSL prober — cipher suites, cert chain, JARM fingerprint
RUN go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest 2>/dev/null || true
# alterx: subdomain permutation generator for DNS bruteforce
RUN go install github.com/projectdiscovery/alterx/cmd/alterx@latest 2>/dev/null || true
# puredns: fast DNS resolver/bruteforcer (depends on massdns at runtime)
RUN go install github.com/d3mondev/puredns/v2@latest 2>/dev/null || true
# hakrawler: fast web crawler
RUN go install github.com/hakluke/hakrawler@latest 2>/dev/null || true
# uncover: search across Shodan/Censys/FOFA/Hunter.io APIs
RUN go install github.com/projectdiscovery/uncover/cmd/uncover@latest 2>/dev/null || true
# cvemap: track CVEs by CVSS/vendor/product from CVE databases
RUN go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest 2>/dev/null || true
# crlfuzz: CRLF injection scanner — try go install, fallback to git clone
RUN go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest 2>/dev/null || \
    (git clone --depth=1 https://github.com/dwisiswant0/crlfuzz.git /tmp/crlfuzz \
     && cd /tmp/crlfuzz/cmd/crlfuzz && go build -o /opt/tools/bin/crlfuzz . \
     && rm -rf /tmp/crlfuzz) || true

# grpcurl: gRPC inspection tool — git clone + build for reliability
RUN git clone --depth=1 https://github.com/fullstorydev/grpcurl.git /tmp/grpcurl && \
    cd /tmp/grpcurl/cmd/grpcurl && go build -o /opt/tools/bin/grpcurl . && \
    rm -rf /tmp/grpcurl || true

# naabu requires CGO for raw packet capture (libpcap).
# Build with CGO_ENABLED=1 using Alpine's musl-compiled libpcap.
# We also copy that musl libpcap into /opt/tools/lib/ so the Debian-based
# web/celery containers (which run these binaries via the musl loader) can
# resolve naabu's libpcap dependency from the shared volume instead of Debian's
# glibc libpcap (which would cause __snprintf_chk symbol-not-found ABI errors).
RUN CGO_ENABLED=1 go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || true

# Ship the Alpine musl libpcap alongside naabu in /opt/tools/lib/.
RUN find /usr/lib -name 'libpcap.so.1.*' | head -1 | xargs -I{} cp {} /opt/tools/lib/ && \
    ln -sf "$(ls /opt/tools/lib/libpcap.so.1.* 2>/dev/null | head -1)" /opt/tools/lib/libpcap.so.1 || true

# Install rustscan — latest stable via cargo (no version pin to avoid crates.io mismatches)
FROM base AS rust-tools
RUN apk add --no-cache rust cargo openssl-dev && \
    mkdir -p /opt/tools/bin && \
    cargo install rustscan --root /opt/tools 2>&1 | tail -5 || true

# Final image
FROM base

COPY --from=go-builder /opt/tools/bin /opt/tools/bin
COPY --from=go-builder /opt/tools/lib /opt/tools/lib
COPY --from=rust-tools /opt/tools/bin /opt/tools/bin

# Install Python-based tools (separate RUN per tool so one failure doesn't block others)
RUN pip3 install --no-cache-dir --break-system-packages wafw00f    2>/dev/null || true
RUN pip3 install --no-cache-dir --break-system-packages sqlmap      2>/dev/null || true
RUN pip3 install --no-cache-dir --break-system-packages droopescan  2>/dev/null || true
# theHarvester: needs aiodns (c-ares), dnspython, aiohttp — system deps in base
# Upgrade pip+wheel first so native extensions compile correctly on Alpine
RUN pip3 install --no-cache-dir --break-system-packages --upgrade pip setuptools wheel 2>/dev/null || true
RUN pip3 install --no-cache-dir --break-system-packages theHarvester 2>&1 | tail -3 || \
    pip3 install --no-cache-dir --break-system-packages \
        aiodns dnspython aiohttp requests netaddr shodan censys \
        git+https://github.com/laramies/theHarvester.git 2>&1 | tail -3 || \
    echo '[theHarvester] install FAILED — skipping'
# wapiti3 — needs lxml (libxml2/libxslt in base), aiohttp; install separately
RUN pip3 install --no-cache-dir --break-system-packages wapiti3 2>&1 | tail -3 || \
    echo '[wapiti3] install FAILED — skipping'
# Install hashcat via apk (GPU password cracker; --cpu-only flag works without GPU)
RUN apk add --no-cache hashcat 2>/dev/null || true

# Install Ruby-based tools (wpscan needs nokogiri native ext dependencies)
RUN apk add --no-cache ruby-nokogiri ruby-json libcurl curl-dev libxml2-dev libxslt-dev 2>/dev/null || true
RUN gem install nokogiri --no-document 2>/dev/null || true
RUN gem install wpscan --no-document 2>/dev/null || true

# Install whatweb
RUN git clone --depth=1 https://github.com/urbanadventurer/WhatWeb.git /opt/tools/whatweb && \
    ln -s /opt/tools/whatweb/whatweb /opt/tools/bin/whatweb

# Install testssl.sh
RUN git clone --depth=1 https://github.com/drwetter/testssl.sh.git /opt/tools/testssl && \
    ln -s /opt/tools/testssl/testssl.sh /opt/tools/bin/testssl.sh

# massdns: high-performance DNS resolver (puredns dependency + standalone use)
# build-base (already in base stage) provides gcc + make. Compile from source.
RUN git clone --depth=1 https://github.com/blechschmidt/massdns.git /tmp/massdns 2>&1 && \
    cd /tmp/massdns && make 2>&1 && \
    cp bin/massdns /opt/tools/bin/massdns && \
    rm -rf /tmp/massdns && \
    echo '[massdns] installed OK' || echo '[massdns] build FAILED — skipping'

# Pull nuclei templates into the shared volume path so they are available
# to web/celery containers. HOME=/opt/tools makes nuclei store templates at
# /opt/tools/.local/share/nuclei-templates which persists in the tools_bin volume.
RUN HOME=/opt/tools /opt/tools/bin/nuclei -update-templates 2>/dev/null || true

# Also create a symlink so nuclei can find templates via XDG path OR legacy root path.
RUN mkdir -p /opt/tools/.local/share && \
    ln -sf /opt/tools/nuclei-templates /opt/tools/.local/share/nuclei-templates 2>/dev/null || true

# Pre-initialise projectdiscovery tool config directories so tools don't fail
# on first run with "no such file or directory / could not parse flags".
# katana v1.5+ requires ~/.config/katana/config.yaml to exist before it runs.
RUN HOME=/opt/tools && \
    mkdir -p /opt/tools/.config/katana   && echo "{}" > /opt/tools/.config/katana/config.yaml   && \
    mkdir -p /opt/tools/.config/httpx    && echo "{}" > /opt/tools/.config/httpx/config.yaml    && \
    mkdir -p /opt/tools/.config/dnsx     && echo "{}" > /opt/tools/.config/dnsx/config.yaml     && \
    mkdir -p /opt/tools/.config/naabu    && echo "{}" > /opt/tools/.config/naabu/config.yaml    && \
    mkdir -p /opt/tools/.config/subfinder && echo "{}" > /opt/tools/.config/subfinder/config.yaml && \
    mkdir -p /opt/tools/.config/nuclei   && \
    true

# Make /opt/tools world-writable so non-root users (e.g., pentools uid=999 in
# web/celery containers) can create config dirs (.config/nuclei, .cache, etc.)
# that tools write at runtime into the shared volume.
RUN chmod -R o+rwX /opt/tools

# Copy built-in wordlists into the container image (also available via bind mount at runtime)
COPY wordlists/ /opt/tools/wordlists/

# Download minimal seclists fallback wordlists if not included
RUN mkdir -p /opt/tools/wordlists/common && \
    wget -q -O /opt/tools/wordlists/common/directory.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt 2>/dev/null || true

ENV PATH="/opt/tools/bin:${PATH}"

# The container copies all built binaries and config into the shared tools_bin volume,
# then prints a manifest. The entrypoint syncs /opt/tools-image/ → /opt/tools/ so
# new tools overwrite whatever was previously in the volume.
RUN cp -r /opt/tools /opt/tools-image

CMD ["sh", "-c", \
  "echo '[pentools-tools] Syncing tools into shared volume...' && \
   find /opt/tools-image -maxdepth 1 -mindepth 1 ! -name 'wordlists' -exec cp -rf {} /opt/tools/ \\; && \
   echo '[pentools-tools] Done. Installed:' && ls /opt/tools/bin/"]
