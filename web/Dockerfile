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
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    # Python-based pentest tools (available system-wide for all module categories)
    pip install --no-cache-dir sqlmap wafw00f

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
