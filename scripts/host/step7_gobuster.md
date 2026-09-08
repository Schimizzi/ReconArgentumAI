# `step7_gobuster.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 7 del pipeline**: usa la herramienta **Gobuster** para **descubrir carpetas y
archivos "ocultos"** de los sitios web del objetivo, probando una lista de nombres típicos
(admin, backup, .git, config, etc.).

Es como "tocar la puerta" con muchos nombres comunes a ver cuál responde, y así encontrar
superficie de ataque que no estaba a la vista.

Gobuster puede trabajar en **tres modos**, según qué haya que probar:

| Modo | Para qué |
|---|---|
| `dir` | Descubre rutas en sitios web. |
| `dns` | Descubre subdominios de un dominio. |
| `tftp` | Busca archivos vía protocolo TFTP (si el objetivo tiene el puerto 69/UDP abierto). |

## ⏱️ ¿Cuándo se usa?

Después de los pasos 2/3 (con la lista de sitios web). Lo corre `run_target.sh`.

## ▶️ Cómo se usa

```bash
# Modo directorios: objetivo, URL, puerto
bash scripts/host/step7_gobuster.sh 10.155.10.15 http://10.155.10.15:8082 8082 dir
```

## 📥 Entrada / 📤 Salida

- **Entrada:** IP del objetivo, la URL (o dominio/IP) y el modo.
- **Salida:** `evidence/<IP>/gobuster_<puerto>.txt` — las rutas encontradas, con su estado
  (ej. `Content (Status: 301)`, `admin (Status: 200)`).

## 🧠 Detalles importantes

- Threads, timeouts y un **corte de tiempo máximo** salen de la configuración de sigilo
  (si un servidor no responde al diccionario completo, lo corta para no quedarse horas).
- Salta la verificación del **certificado TLS** (opción `-k`): los equipos embebidos de la
  LAN (Avaya IP Office, etc.) usan certificados autofirmados; sin `-k` Gobuster fallaba el
  arranque y cada consulta se colgaba hasta el corte de tiempo (caso detectado en Kali).
- Solo reporta respuestas 200/204/301/307/403 (lo que vale la pena anotar).
- Si no hay sitios web ni dominio ni TFTP, el paso se marca como "saltado".