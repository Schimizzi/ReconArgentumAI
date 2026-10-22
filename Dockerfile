# syntax=docker/dockerfile:1
FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="ReconArgentumAI - pentest recon env"
ENV DEBIAN_FRONTEND=noninteractive

# 1) Base + tools via apt (nmap, nikto, whatweb, gobuster, jq, httpx-toolkit, nuclei) + deps
# UNIFICACION KALI/DOCKER (2026-09-07): se agregan samba-client (Step 10 SMB Enum)
# e iputils-ping (preflight + ping gate del Step 10) para que el Agente 1 completo
# (Steps 1-11) corra dentro del contenedor SIN necesitar un LLM, igual que en la VM.
# STEP 11 (2026-10-21): se agrega enum4linux-ng (enumeracion AD anonima; solo Linux;
# en macOS el Step 11 no se ejecuta).
# UNIFICACION PD/APT (2026-09-09): httpx (ProjectDiscovery) y nuclei se instalan con los
# paquetes de Kali (httpx-toolkit, nuclei) en vez de los binarios oficiales de GitHub.
RUN apt-get update && apt-get install -y --no-install-recommends nmap nikto whatweb gobuster jq httpx-toolkit nuclei samba-client iputils-ping enum4linux-ng ldap-utils git curl ca-certificates unzip xz-utils python3 python3-pip hydra && rm -rf /var/lib/apt/lists/*

# 2) SecLists (wordlists para gobuster/dirsearch/nuclei custom)
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists

# 3) SSLyze (Python) - pip
RUN python3 -m pip install --no-cache-dir --break-system-packages sslyze

# 4) Workspace
WORKDIR /workspace

# Sanity check: el build FALLA si falta alguna de las 10 tools del Agente 1 + jq + hydra (manual)
RUN set -eux; command -v nmap; command -v httpx-toolkit; command -v nuclei; command -v nikto; command -v whatweb; command -v gobuster; command -v sslyze; command -v smbclient; command -v enum4linux-ng; command -v ldapsearch; command -v ping; command -v jq; command -v hydra

CMD ["bash"]
