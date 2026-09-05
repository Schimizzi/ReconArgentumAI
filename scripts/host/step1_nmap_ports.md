# `step1_nmap_ports.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 1 del escaneo** en su versión para **modo Host (Mac)**. Usa **Nmap** para descubrir
qué **puertos/servicios** de un objetivo están abiertos.

En la Mac no hay permisos privilegiados para el escaneo "sigiloso", por eso acá Nmap se usa en
modo "Connect Scan" (`-sT`), que es el que funciona sin privilegios de administrador.

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

- Revisa los **1000 puertos más comunes** y solo reporta los **abiertos**.
- No hace resolución de nombres DNS (más rápido y directo).
- Retries y tiempos de espera salen de la configuración de sigilo (`config/stealth.yaml`), no
  están "a dedo".
- Al inicio **limpia** resultados anteriores del mismo objetivo para no mezclar escaneos.