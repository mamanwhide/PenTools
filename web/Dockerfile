FROM python:3.12-slim

# System dependencies
# musl: allows Alpine-compiled Go binaries (tools container) to run on Debian.
# The Alpine musl linker requires /lib/ld-musl-x86_64.so.1; Debian musl provides
# the actual loader at /usr/lib/x86_64-linux-musl/libc.so — symlink it correctly.
# nmap: installed natively here (Alpine static build is unreliable with PCAP).
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    build-essential \
    libpq-dev \
    musl \
    nmap \
    # WeasyPrint system libraries (GLib, Pango, Cairo, fonts)
    libglib2.0-0 \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libfontconfig1 \
    libharfbuzz0b \
    libffi8 \
    shared-mime-info \
    fonts-noto-core \
    # DNS utilities (dig, nslookup) — used by DNS enumeration modules
    bind9-dnsutils \
    # hashcat — GPU/CPU password recovery tool
    hashcat \
    # Ruby + wpscan dependencies
    ruby \
    ruby-dev \
    libcurl4-openssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    # wapiti3 / theHarvester build dependencies
    libffi-dev \
    # Required for rustscan archive extraction
    unzip \
    && rm -rf /var/lib/apt/lists/* \
    # The Alpine-built Go binaries in tools_bin require musl libc and the musl ELF loader.
    # Debian musl package provides: /usr/lib/x86_64-linux-musl/libc.so (the actual loader).
    # Create the ld-musl linker path + libc.musl alias that Alpine binaries expect.
    && ln -sf /usr/lib/x86_64-linux-musl/libc.so /lib/ld-musl-x86_64.so.1 \
    && ln -sf /usr/lib/x86_64-linux-musl/libc.so /lib/libc.musl-x86_64.so.1 \
    # naabu links against libpcap.so.1 (musl). musl's loader searches /etc/ld-musl-x86_64.path.
    # /opt/tools/lib contains Alpine's musl-compiled libpcap (shipped from tools container via
    # shared volume). It must come FIRST so musl finds the musl libpcap before Debian's glibc
    # libpcap (which would cause __snprintf_chk ABI errors).
    && echo '/opt/tools/lib:/lib:/lib/x86_64-linux-gnu:/usr/lib:/usr/lib/x86_64-linux-gnu' > /etc/ld-musl-x86_64.path \
    # Debian installs libpcap as .so.1.10.5 with .so.0.8 alias only; add the .so.1 alias.
    && ln -sf libpcap.so.1.10.5 /usr/lib/x86_64-linux-gnu/libpcap.so.1

# Create non-root app user
RUN groupadd -r pentools && useradd -r -g pentools -d /app -s /sbin/nologin pentools

WORKDIR /app

# Install Python dependencies first (layer cache optimization)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    # Python-based pentest tools (available system-wide for all module categories)
    pip install --no-cache-dir sqlmap wafw00f && \
    # theHarvester — OSINT multi-source recon tool
    # PyPI has a stub theHarvester-0.0.1 that is NOT the real tool; install from GitHub directly
    pip install --no-cache-dir \
        aiodns dnspython aiohttp requests netaddr \
        git+https://github.com/laramies/theHarvester.git \
    2>/dev/null || echo '[theHarvester] install FAILED — skipping' && \
    # wapiti3 — web application vulnerability scanner
    pip install --no-cache-dir wapiti3 2>/dev/null || echo '[wapiti3] install FAILED — skipping'

# Install rustscan — use pre-built x86_64 binary from GitHub releases (Cargo 1.78 lacks edition2024)
RUN RUSTSCAN_URL="https://github.com/bee-san/RustScan/releases/download/2.4.1/x86_64-linux-rustscan.tar.gz.zip" && \
    wget -qO /tmp/rustscan.zip "${RUSTSCAN_URL}" && \
    cd /tmp && unzip -q rustscan.zip && \
    tar -xzf /tmp/x86_64-linux-rustscan.tar.gz -C /tmp && \
    install -m 755 /tmp/rustscan /usr/local/bin/rustscan && \
    rm -f /tmp/rustscan.zip /tmp/x86_64-linux-rustscan.tar.gz /tmp/rustscan && \
    echo "[rustscan] $(rustscan --version 2>/dev/null || echo 'installed OK')"

# Install wpscan — Ruby-based WordPress vulnerability scanner
RUN gem install --no-document nokogiri wpscan 2>/dev/null || echo '[wpscan] gem install FAILED — skipping'

# wapiti installs binary as 'wapiti'; add 'wapiti3' alias for compatibility
RUN ln -sf /usr/local/bin/wapiti /usr/local/bin/wapiti3 2>/dev/null || true

# Add tools volume mount path to PATH
ENV PATH="/opt/tools/bin:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy app code
COPY --chown=pentools:pentools . .

# Copy entrypoint scripts (placed in web/scripts/ at build time)
COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh && \
    chown -R pentools:pentools /scripts

# Ensure volumes that will be mounted can be written by pentools
RUN mkdir -p /app/staticfiles /tmp/pentools && \
    chown -R pentools:pentools /app/staticfiles /tmp/pentools

# Run as non-root
USER pentools

EXPOSE 8000
