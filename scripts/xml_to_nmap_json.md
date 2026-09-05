# `xml_to_nmap_json.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Convierte un resultado de **Nmap en formato XML a formato JSON**.

Nmap (la herramienta que descubre puertos/servicios) puede guardar sus resultados en varios
formatos de archivo. El resto del proyecto prefiere el formato **JSON**, pero por un problema
puntual de una versión de Nmap en Kali el JSON sale mal. Este script lo arregla: **lee el XML
(bueno) y genera el JSON (necesario)**.

## ⏱️ ¿Cuándo se usa?

Lo llaman otros scripts automáticamente después de cada escaneo de Nmap (pasos 1 y 3). No lo
corrés a mano normalmente.

## ▶️ Cómo se usa

```bash
python3 scripts/xml_to_nmap_json.py <entrada.xml> <salida.json>
```

## 📥 Entrada / 📤 Salida

- **Entrada:** un archivo XML de Nmap (ej. `nmap_ports.xml`).
- **Salida:** un archivo JSON con lo mismo, en el formato que el proyecto entiende
  (por qué puertos están abiertos, con su servicio, versión y detalles).

## ⚠️ Notas

- Solo sirve para **escaneos de Nmap** (no convierte cualquier XML, sino el formato específico
  que genera Nmap).
- Existe porque en la imagen de Kali del proyecto el flag `-oJ` (JSON directo de Nmap) está roto;
  el XML sí funciona, así que se busca el JSON a partir de ahí.