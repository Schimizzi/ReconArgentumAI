# `step11_ldap_enum.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es un script de **enumeración LDAP/Active Directory con `ldapsearch`** (el mismo cliente que se usa a
mano). Primer paso de la fase AD: pregunta al servidor LDAP quién es (root DSE) y, si el modo
credencializado fue aprobado, qué usuarios y qué *service principal names* (SPN) expone. Es el
**Step 11** del pipeline y **corre en Linux y en macOS**.

## ⏱️ ¿Cuándo se usa?

Cuando la evidencia del target (Step 3) muestra el **puerto 389, 636, 3268 o 3269** abierto. Es la
consulta AD más barata y menos ruidosa: va **antes** de Enum4linux (Step 12).

## ▶️ Cómo se usa

### Modo manual (bajo demanda)

```bash
bash scripts/host/step11_ldap_enum.sh <IP>
bash scripts/host/step11_ldap_enum.sh --all
bash scripts/host/step11_ldap_enum.sh <IP> --force
bash scripts/host/step11_ldap_enum.sh <IP> --tls                     # fuerza LDAPS (636/3269)
# MODO CREDENCIALIZADO (OPT-IN: requiere aprobación en Fase 0)
bash scripts/host/step11_ldap_enum.sh <IP> --ldap-user usuario@dominio --ldap-pass ******
```

### Modo pipeline (lo llama el Step 11 de `run_target.sh`, siempre anónimo)

```bash
bash scripts/host/step11_ldap_enum.sh --ev-dir evidence/<IP> --force --no-ping-check
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `nmap_detailed.xml` del Step 3 (de ahí sale si 389/636/3268/3269 están abiertos).
- **Salida** (en la carpeta del target):
  - `ldapsearch.txt` — **root DSE** crudo (la **primera línea es el comando**; si hubo password dice `<REDACTED>`).
  - `ldapsearch_domain.txt` — objeto raíz del dominio (si el root DSE trajo el base DN).
  - `ldapsearch_users.txt` / `ldapsearch_spn.txt` — solo en modo credencializado.
  - Resumen de la corrida `--all`: `CLIENTE/ldapsearch_checks/ldapsearch_summary.txt`.

## ⚠️ Notas

- **Gate de servicio:** sin 389/636/3268/3269 -> `skipped_no_ldap`, sin tráfico. Sin `ldapsearch` en el
  PATH -> `skipped`. Gate de ping: si no responde -> `skipped_no_ping`.
- **Modo anónimo por defecto**; el credencializado es **opt-in** y hay que aprobarlo en Fase 0.
- **El password nunca queda en la evidencia:** se pasa por archivo temporal 0600 (`-y`) y se redacta.
- **Solo lectura (R2)**; timeout desde `config/stealth.yaml` (`ldapsearch_timeout_seconds`, R5).
- **Evidencia condicional:** cada archivo se conserva solo si trajo datos.
- **No-clobber:** si `ldapsearch.txt` ya existe, avisa `[SKIP]`; usá `--force`.
- **Ética/alcance:** solo sobre infraestructura **autorizada**.
