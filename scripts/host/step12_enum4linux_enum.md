# `step12_enum4linux_enum.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es un script de **enumeración de Active Directory con `enum4linux`** (usuarios, grupos, política de
contraseñas, recursos compartidos e información de dominio) usando **sesión nula o anónima** (sin
usuario ni contraseña) sobre objetivos con **SMB abierto** (puertos 139 y 445). Es el **Step 12** del
pipeline de reconocimiento.

⚠️ **Solo corre en Linux** (VM Debian/Kali o el contenedor Docker). En **macOS** el script **no
ejecuta nada**: informa `skipped_unsupported_os` y termina **sin generar tráfico** hacia el objetivo.

## ⏱️ ¿Cuándo se usa?

Cuando ya se escaneó un objetivo con el pipeline y en su evidencia aparece que tiene el **puerto 139
o 445 abierto**. Sirve para saber qué información de dominio expone ese equipo por sesión anónima.

Vive en `scripts/host/` y tiene dos modos:

- **Modo manual** (bajo demanda sobre `CLIENTE/`): el flujo de siempre.
- **Modo pipeline** (`--ev-dir`): lo invoca `run_target.sh` como **Step 12**, apuntando directo a
  `evidence/<IP>/`.

## ▶️ Cómo se usa

### Modo manual (bajo demanda)

```bash
# Desde la raíz del proyecto. Acepta la IP pura o la carpeta con sufijo _vuln/_no_vuln:
bash scripts/host/step12_enum4linux_enum.sh <IP>

# TODOS los targets de CLIENTE con nmap_detailed.xml (secuencial, 1 por vez):
bash scripts/host/step12_enum4linux_enum.sh --all

# Con otra carpeta de proyecto:
bash scripts/host/step12_enum4linux_enum.sh <IP> OTRO_CLIENTE

# Re-enumerar aunque exista evidencia previa (la sobrescribe):
bash scripts/host/step12_enum4linux_enum.sh <IP> --force

# Saltar el chequeo de ping (solo si el host bloquea ICMP):
bash scripts/host/step12_enum4linux_enum.sh <IP> --no-ping-check

# RID cycling (RUÍDOSO - SOLO si la Fase 0 lo aprobó):
bash scripts/host/step12_enum4linux_enum.sh <IP> --rid
```

### Modo pipeline (lo llama el Step 12 de `run_target.sh`)

```bash
bash scripts/host/step12_enum4linux_enum.sh --ev-dir evidence/10.150.40.155 --force --no-ping-check
```

> En **macOS** estos comandos devuelven `skipped_unsupported_os` **sin tocar la red**.

## 📥 Entrada / 📤 Salida

- **Entrada:** el `nmap_detailed.xml` del Step 3 (de ahí sale si 139/445 están abiertos y el
  workgroup/dominio). En modo manual se busca en `CLIENTE/<IP>/outputs/`; en modo pipeline, en `<DIR>/`.
- **Salida** (en la carpeta del target: `CLIENTE/<IP>/outputs/` manual, `evidence/<IP>/` pipeline):
  - `enum4linux.txt` — salida cruda completa (la **primera línea es el comando** ejecutado).
  - `enum4linux.json` / `enum4linux.yaml` — export estructurado de `enum4linux-ng` (`-oA`), para el Agente 6.
  - Resumen de la corrida `--all`: `CLIENTE/enum4linux_checks/enum4linux_summary.txt`.

## ⚠️ Notas

- **No se ejecuta en macOS** (decisión del proyecto): `uname -s` = Darwin -> `skipped_unsupported_os`,
  sin tráfico. El binario `enum4linux-ng` no existe en macOS.
- **Gate de servicio:** sin 139/445 abiertos -> `skipped_no_smb` y no genera tráfico. Si no hay
  `enum4linux-ng` ni `enum4linux` en el PATH (Linux) -> `skipped`.
- **Gate de ping:** verifica un ping antes de tocar el target (timeout en `config/stealth.yaml`); si
  no responde -> `skipped_no_ping` y no ejecuta nada.
- **Solo lectura y sin credenciales (R2):** nunca usa `-u`/`-p`/`-H`/`-K` ni `-A` (esa opción hace
  escrituras de prueba en los shares). RID cycling (`--rid`) es **opt-in** y requiere aprobación en
  Fase 0 (genera cientos de lookups visibles en el AD).
- **Timeout desde `config/stealth.yaml`** (`enum4linux_timeout_seconds`), nunca hardcodeado (R5).
- **Evidencia condicional:** solo se conserva `enum4linux.*` si hubo sesión establecida y al menos
  una sección con datos; si no, se elimina (ruido sin hallazgo) y se conserva únicamente la
  **nota del rechazo** `enum4linux_sin_sesion.txt` (comando + motivo literal, ej.
  `NT_STATUS_LOGON_FAILURE`). Esa nota la declara el `manifest.json` y el Agente 6 la reporta como
  hallazgo informativo *"Sesion SMB anonima rechazada (enum4linux)"* (antes el rechazo se perdía).
  Se anuncia en consola con `STEP_ENUM4LINUX_NOTE sin_sesion`.
- **No-clobber:** si `enum4linux.txt` ya existe, muestra `[SKIP]` y no lo sobrescribe; usá `--force`.
- **Ética/alcance:** solo sobre infraestructura **autorizada**. Enumerar un dominio sin permiso es
  acceso no autorizado a información.
