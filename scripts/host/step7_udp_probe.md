# `step7_udp_probe.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es un **chequeo auxiliar del paso 7**: sondea con Nmap si el objetivo tiene **abierto el puerto
69/UDP (protocolo TFTP)**.

El resultado se usa para decidir el **modo `tftp` de Gobuster**: si el puerto TFTP está abierto,
se aprovecha a buscar archivos también por ese protocolo; si no, se lo deja de lado.

## ⏱️ ¿Cuándo se usa?

Lo llama el runner `run_target.sh` antes de definir qué modos de Gobuster correr.

## ▶️ Cómo se usa

```bash
bash scripts/host/step7_udp_probe.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** la IP del objetivo.
- **Salida:**
  - `evidence/<IP>/udp_69.gnmap` — el resultado crudo del sondeo.
  - Mensaje final: `STEP7_UDP_OPEN port=69` (abierto) o `STEP7_UDP_CLOSED port=69` (cerrado),
    que es lo que usa el runner para decidir.

## 🧠 Detalles importantes

- El puerto, la velocidad y los reintentos del sondeo salen de `config/stealth.yaml`.
- Es un único sondeo puntual (1 puerto), por lo que genera muy poco tráfico.