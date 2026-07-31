# CoordiNext PRO AA v10.6.1 · Panel Web Supabase

Mismo panel web administrativo, migrado de `control_github.json` a Supabase.

La interfaz se publica desde `docs/index.html`. El archivo `docs/panel-config.js` contiene únicamente la URL del proyecto y la clave pública publishable.

## Instalación

1. Ejecutar `supabase/PANEL_WEB_SQL.sql` en SQL Editor.
2. Desplegar `supabase/functions/admin-users` con el nombre `admin-users`.
3. Publicar la carpeta `docs` con GitHub Pages.

El token de GitHub ya no forma parte del flujo administrativo.
