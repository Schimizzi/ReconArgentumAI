# `gobuster_urls.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Arma una **lista única de direcciones web** a partir de todos los resultados de la herramienta
**Gobuster** (la que descubre carpetas y archivos "ocultos" de un sitio web).

Como Gobuster se ejecuta una vez por puerto de cada equipo, sus resultados quedan en muchos
archivos sueltos. Este script los junta todos en **un solo archivo de texto** con una URL completa
por línea, listo para que otros scripts lo lean (por ejemplo `check_gobuster_urls.sh`).

## ⏱️ ¿Cuándo se usa?

Después de correr el paso 7 del escaneo (Gobuster), cuando querés preparar la evidencia para un
análisis más profundo de las URLs descubiertas.

## ▶️ Cómo se usa

```bash
# Básico (lee CLIENTE/*/outputs/gobuster_*.txt → CLIENTE/gobuster_urls_curl.txt)
bash scripts/gobuster_urls.sh

# Con carpeta de proyecto y archivo de salida personalizados
bash scripts/gobuster_urls.sh CLIENTE CLIENTE/gobuster_urls_curl.txt
```

## 📥 Entrada / 📤 Salida

- **Entrada:** los archivos de resultados de Gobuster de cada objetivo
  (`CLIENTE/<IP>/outputs/gobuster_*.txt`).
- **Salida:** `CLIENTE/gobuster_urls_curl.txt` — una línea por URL, por ejemplo:
  ```
  http://10.155.10.15:8082/Content
  http://10.155.10.15:8082/Images
  ```

## ⚠️ Notas

- Reconstruye cada URL completa cruzando: la ruta (de Gobuster), la IP (del nombre de la carpeta
  del objetivo) y el puerto (del nombre del archivo).
- Detecta si el puerto es HTTP o HTTPS según la evidencia de HTTPX.