# add-php2shell-watchlist-and-qa-hardening

Incorpora al pipeline la vulnerabilidad crítica de la semana (**PHP2Shell**: `CVE-2026-109618` /
`CVE-2026-109619`, RCE no autenticado en PHP 5.4–8.5, CVSS 9.2) mediante una **advisory watchlist
local**, un **auditor offline** y un **check de QA bloqueante (CK-10)**; y corrige tres defectos
detectados en el mismo run: `target_id` duplicados en `scope.json`, `CK-03` que trataba como
corrupción los JSONL/vacíos, y `CK-05` que contradecía su propio spec.
