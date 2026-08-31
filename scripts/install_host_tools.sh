#!/bin/bash
# Instalador de tools MODO HOST (macOS) — nikto, gobuster (brew); sslyze (pipx);
# whatweb (git clone a tools/WhatWeb, no hay fórmula brew).
set -u
WS="/Users/claudio/OpenSpec_project/ReconArgentumAI"
export PATH="$HOME/.local/bin:$PATH"

{
  echo "=== brew install nikto gobuster ==="
  brew install nikto gobuster 2>&1 | tail -6

  echo "=== brew install pipx ==="
  brew install pipx 2>&1 | tail -3

  echo "=== pipx install sslyze ==="
  if command -v sslyze >/dev/null 2>&1; then
    echo "sslyze ya presente: $(command -v sslyze)"
  else
    pipx install sslyze 2>&1 | tail -10
  fi

  echo "=== WhatWeb (git clone) ==="
  if [ -x "$WS/tools/WhatWeb/whatweb" ]; then
    echo "WhatWeb ya presente en $WS/tools/WhatWeb"
  else
    git clone --depth 1 https://github.com/urbanadventurer/WhatWeb "$WS/tools/WhatWeb" 2>&1 | tail -3
  fi
  echo "=== test whatweb ==="
  (cd "$WS/tools/WhatWeb" && ruby whatweb --version 2>&1 | head -3) || echo WHATWEB_TEST_FAIL

  echo "=== verificacion final ==="
  for t in nmap nikto gobuster jq httpx-pd nuclei; do
    printf '%s: ' "$t"; command -v "$t" 2>/dev/null || echo FALTA-PATH
  done
  printf 'sslyze: '; command -v sslyze 2>/dev/null || echo FALTA-PATH
  printf 'whatweb-local: '; ls "$WS/tools/WhatWeb/whatweb" 2>/dev/null || echo FALTA
} > /tmp/tools_install2.log 2>&1
echo INSTALL2_FINALIZADO >> /tmp/tools_install2.log