# `make_report.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **generador de informes de la fase de escaneo** (en el proyecto se lo llama "Agente 5 -
Reporter"). Lee la evidencia de todos los objetivos y arma:

- **Un informe final consolidado** (`.md` y `.json`) con todos los objetivos.
- **Un informe individual por cada objetivo**.

## ⏱️ ¿Cuándo se usa?

Después de escanear (Fase 1) y de investigar vulnerabilidades. Genera la primera versión del
informe que después se consolida en la entrega final.

## ▶️ Cómo se usa

```bash
python3 scripts/host/make_report.py
```

Se ejecuta una vez terminadas las fases de escaneo (Fase 1) y de análisis (Fase 2): lee la
evidencia de todos los targets y escribe los informes en `reports/`. No acepta argumentos.

## 📥 Entrada / 📤 Salida

- **Entrada:** la evidencia de `evidence/<IP>/` (MANIFEST de cada objetivo, resultados de
  herramientas, CVEs) y la configuración (`scope.json`, `stealth.yaml`).
- **Salida:** los informes en la carpeta `reports/`:
  - `final_report.md` / `.json` — resumen de toda la corrida.
  - `<objetivo>_report.md` / `.json` — detalle por objetivo.

## 🧠 Detalles importantes

- **Escala de riesgo:** usa el puntaje CVSS para etiquetar: 9+ = CRÍTICO, 7+ = ALTO, 4+ = MEDIO,
  resto BAJO.
- **Ofuscación:** contraseñas, tokens, API keys y credenciales se escriben como `***` en los
  informes (la evidencia original no se toca).
- **Registra la metodología:** incluye en el informe la configuración de sigilo usada y el estado
  de cada paso por objetivo.