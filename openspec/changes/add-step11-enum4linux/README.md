# add-step11-enum4linux

Step 11 - Enum4linux (enum4linux-ng, fallback enum4linux). Enumera usuarios, grupos, politica de
passwords, shares e informacion de dominio via sesion anonima/nula SMB en targets con TCP 139/445
abiertos, con gate Service-Based, timeout desde `config/stealth.yaml`, modo pasivo por defecto (sin
credenciales), guard de plataforma (no se ejecuta en macOS) y evidencia trazable en
`evidence/<target>/` / `CLIENTE/<ip>/outputs/` para el Agente 6.
