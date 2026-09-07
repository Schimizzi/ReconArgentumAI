# syntax=docker/dockerfile:1
FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="ReconArgentumAI - pentest recon env"
ENV DEBIAN_FRONTEND=noninteractive \
    HTTPX_VERSION=1.10.0 \
    NUCLEI_VERSION=3.11.1

# 1) Base + tools vía apt (nmap, nikto, whatweb, gobuster, jq) + deps
# UNIFICACIÓN KALI/DOCKER (2026-09-07): se agregan samba-client (Step 10 SMB Enum)
# e iputils-ping (preflight + ping gate del Step 10) para que el Agente 1 completo
# (Steps 1-10) corra dentro del contenedor SIN necesitar un LLM, igual que en la VM.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap nikto whatweb gobuster jq \
        samba-client iputils-ping \
        git curl ca-certificates unzip xz-utils \
        python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# 2) SecLists (wordlists para gobuster/dirsearch/nuclei custom)
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists

# 3) HTTPX (ProjectDiscovery) — binario oficial (no hay paquete apt)
RUN curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" -o /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip httpx -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && ln -sf httpx /usr/local/bin/httpx-pd \
    && rm -f /tmp/httpx.zip

# 4) Nuclei (ProjectDiscovery) — binario oficial (no hay paquete apt)
RUN curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip

# 5) SSLyze (Python) — pip
RUN python3 -m pip install --no-cache-dir --break-system-packages sslyze

# 6) Workspace
WORKDIR /workspace

# Sanity check: el build FALLA si falta alguna de las 9 tools del Agente 1 + jq
RUN set -eux; \
    command -v nmap; command -v httpx-pd; command -v nuclei; \
    command -v nikto; command -v whatweb; command -v gobuster; \
    command -v sslyze; command -v smbclient; \
    command -v ping; command -v jq

CMD ["bash"]