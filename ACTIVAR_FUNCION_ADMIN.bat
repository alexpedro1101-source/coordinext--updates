@echo off
setlocal
cd /d "%~dp0supabase"
echo.
echo CoordiNext PRO AA - Activar funcion segura admin-users
echo Se abrira el inicio de sesion de Supabase.
echo.
where npx >nul 2>&1
if errorlevel 1 (
  echo ERROR: Instale Node.js LTS para disponer de npx.
  pause
  exit /b 1
)
npx --yes supabase@latest login
if errorlevel 1 goto error
npx --yes supabase@latest functions deploy admin-users --project-ref dptgxjrzenotiigvwetu
if errorlevel 1 goto error
echo.
echo FUNCION ADMIN-USERS PUBLICADA CORRECTAMENTE.
pause
exit /b 0
:error
echo.
echo No se pudo completar. Revise el mensaje anterior.
pause
exit /b 1
