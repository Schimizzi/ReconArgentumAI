# `step1_nmap_ports.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 1 del escaneo** (script unificado: modo Host, VM Kali y contenedor Docker). Usa **Nmap** para descubrir
qué **puertos/servicios** de un objetivo están abiertos.

El tipo de escaneo se **autodetecta por privilegios**: si el proceso corre como **root** (VM Kali, contenedor) usa el escaneo **SYN** (`-sS`);
si no (Mac sin sudo) usa **"Connect Scan"** (`-sT`), que funciona sin privilegios.

## ⏱️ ¿Cuándo se usa?

Siempre que `run_target.sh` escanea una IP; es el primer paso.

## ▶️ Cómo se usa

```bash
bash scripts/host/step1_nmap_ports.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** la IP del objetivo.
- **Salida:** en `evidence/<IP>/` los archivos `nmap_ports.xml`, `.txt`, `.gnmap` y `nmap_ports.json`.

## 🧠 Detalles importantes

- Escanea la **lista de puertos del cliente** definida en `config/stealth.yaml` (`clienteP`, reemplaza el antiguo `--top-ports 1000`); si no está definida, usa los **1000 puertos más comunes**. Solo reporta los **abiertos**.
- No hace resolución de nombres DNS (más rápido y directo).
- Retries y tiempos de espera salen de la configuración de sigilo (`config/stealth.yaml`), no
  están "a dedo".
- Al inicio **limpia** resultados anteriores del mismo objetivo para no mezclar escaneos.