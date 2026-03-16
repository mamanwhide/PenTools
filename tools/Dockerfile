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

# Install rustscan (pinned to last stable release — latest can break with Rust API changes)
FROM base AS rust-tools
RUN apk add --no-cache rust cargo && \
    mkdir -p /opt/tools/bin && \
    cargo install rustscan --version 2.3.0 --root /opt/tools 2>/dev/null || \
    cargo install rustscan --root /opt/tools 2>/dev/null || true

# Final image
FROM base

COPY --from=go-builder /opt/tools/bin /opt/tools/bin
COPY --from=go-builder /opt/tools/lib /opt/tools/lib
COPY --from=rust-tools /opt/tools/bin /opt/tools/bin

# Install Python-based tools (separate RUN per tool so one failure doesn't block others)
RUN pip3 install --no-cache-dir --break-system-packages wafw00f    2>/dev/null || true
RUN pip3 install --no-cache-dir --break-system-packages sqlmap      2>/dev/null || true
RUN pip3 install --no-cache-dir --break-system-packages droopescan  2>/dev/null || true
# theHarvester: needs specific deps; install with fallback
RUN pip3 install --no-cache-dir --break-system-packages theHarvester 2>/dev/null || \
    pip3 install --no-cache-dir --break-system-packages git+https://github.com/laramies/theHarvester.git 2>/dev/null || true
# wapiti3 — large dependency tree; install separately
RUN pip3 install --no-cache-dir --break-system-packages wapiti3 2>/dev/null || true
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
# Compiled from source. Ensure build deps are present and use make install.
RUN apk add --no-cache make 2>/dev/null || true && \
    git clone --depth=1 https://github.com/blechschmidt/massdns.git /tmp/massdns && \
    cd /tmp/massdns && make && cp bin/massdns /opt/tools/bin/massdns && \
    rm -rf /tmp/massdns || true

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

# Copy built-in wordlists
COPY wordlists/ /wordlists/

# Download minimal wordlists if not included
RUN mkdir -p /wordlists/common && \
    wget -q -O /wordlists/common/directory.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt 2>/dev/null || true

ENV PATH="/opt/tools/bin:${PATH}"

# The container just ensures binaries exist in the shared volume, then exits
CMD ["sh", "-c", "echo '[pentools-tools] All tools installed in /opt/tools/bin' && ls /opt/tools/bin/"]
