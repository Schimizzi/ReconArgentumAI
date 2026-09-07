# `run_fase1_run3.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **runner maestro de la fase de escaneo**: recorre toda la lista de objetivos autorizados
(`authorized_targets`) de la configuración y, **uno por uno**, llama a `run_target.sh` (que
escanea cada IP con sus 10 pasos).

Entre un objetivo y el siguiente espera un tiempo (por defecto **5 minutos**, configurable) para
no hacer ruido en la red y respetar el sigilo.

## ⏱️ ¿Cuándo se usa?

Cuando se quiere escanear **toda la lista de objetivos de una vez** (la "Fase 1"). Es lo que
corre el auditor para procesar todos los equipos autorizados en secuencia.

## ▶️ Cómo se usa

```bash
# Escanea todos los objetivos autorizados, en orden
bash scripts/host/run_fase1_run3.sh

# Solo simular: mostrar qué se ejecutaría, sin escanear nada
bash scripts/host/run_fase1_run3.sh --dry-run
```

## 📥 Entrada / 📤 Salida

- **Entrada:** la lista de objetivos de `config/scope.json`.
- **Salida:** la carpeta `evidence/<IP>/` de cada objetivo + un **log por objetivo** en
  `logs/fase1_<IP>.log` con todo lo que pasó.

## ⚠️ Notas — guarda reglas internas

- **R1 (scope):** antes de cada objetivo vuelve a verificar que siga autorizado y no excluido; si
  no lo está, lo salta y lo anota.
- Es **secuencial**: no dispara dos objetivos a la vez (lo pide la configuración de sigilo).
- El nombre "run3" viene de la **tercera vuelta** de escaneo del proyecto (cada vuelta ajusta
  objetivos y velocidad según lo que pidió el cliente).