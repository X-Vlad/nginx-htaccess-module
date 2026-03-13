@echo off
title nginx-htaccess-module Demo Manager
cd /d "%~dp0"

:menu
cls
echo ==============================================
echo   nginx-htaccess-module Demo Manager
echo ==============================================
echo.
echo   --- Simple Demo (PHP-FPM) ---
echo    1. Build + Start
echo    2. Rebuild (no cache) + Start
echo    3. Stop
echo    4. Logs (follow)
echo    5. Logs (last 50 lines)
echo.
echo   --- WordPress Demo (PHP-FPM + MySQL) ---
echo    6. Build + Start
echo    7. Rebuild (no cache) + Start
echo    8. Stop
echo    9. Logs (follow)
echo   10. Logs (last 50 lines)
echo.
echo   --- Utils ---
echo   11. Shell into nginx container
echo   12. Shell into php container
echo   13. Stop ALL containers
echo   14. Run unit tests
echo.
echo    0. Exit
echo.
echo ==============================================
set /p choice="Select: "

if "%choice%"=="1" goto simple_start
if "%choice%"=="2" goto simple_rebuild
if "%choice%"=="3" goto simple_stop
if "%choice%"=="4" goto simple_logs
if "%choice%"=="5" goto simple_logs_tail
if "%choice%"=="6" goto wp_start
if "%choice%"=="7" goto wp_rebuild
if "%choice%"=="8" goto wp_stop
if "%choice%"=="9" goto wp_logs
if "%choice%"=="10" goto wp_logs_tail
if "%choice%"=="11" goto shell_nginx
if "%choice%"=="12" goto shell_php
if "%choice%"=="13" goto stop_all
if "%choice%"=="14" goto unit_tests
if "%choice%"=="0" goto end

echo Invalid choice
timeout /t 2 >nul
goto menu

:simple_start
echo.
echo Building and starting Simple Demo...
docker compose -f docker-compose.yml build
docker compose -f docker-compose.yml up -d
echo.
echo Demo available at: http://localhost:8080
pause
goto menu

:simple_rebuild
echo.
echo Rebuilding (no cache) and starting Simple Demo...
docker compose -f docker-compose.yml down
docker compose -f docker-compose.yml build --no-cache
docker compose -f docker-compose.yml up -d
echo.
echo Demo available at: http://localhost:8080
pause
goto menu

:simple_stop
echo.
docker compose -f docker-compose.yml down
echo Simple Demo stopped.
pause
goto menu

:simple_logs
echo.
echo Press Ctrl+C to stop following logs...
docker compose -f docker-compose.yml logs -f
pause
goto menu

:simple_logs_tail
echo.
docker compose -f docker-compose.yml logs --tail=50
pause
goto menu

:wp_start
echo.
echo Building and starting WordPress Demo...
docker compose -f docker-compose.wordpress.yml build
docker compose -f docker-compose.wordpress.yml up -d
echo.
echo WordPress available at: http://localhost:8080
echo MySQL: host=mysql db=wordpress user=wp pass=wppass
pause
goto menu

:wp_rebuild
echo.
echo Rebuilding (no cache) and starting WordPress Demo...
docker compose -f docker-compose.wordpress.yml down
docker compose -f docker-compose.wordpress.yml build --no-cache
docker compose -f docker-compose.wordpress.yml up -d
echo.
echo WordPress available at: http://localhost:8080
echo MySQL: host=mysql db=wordpress user=wp pass=wppass
pause
goto menu

:wp_stop
echo.
docker compose -f docker-compose.wordpress.yml down
echo WordPress Demo stopped.
pause
goto menu

:wp_logs
echo.
echo Press Ctrl+C to stop following logs...
docker compose -f docker-compose.wordpress.yml logs -f
pause
goto menu

:wp_logs_tail
echo.
docker compose -f docker-compose.wordpress.yml logs --tail=50
pause
goto menu

:shell_nginx
echo.
echo Connecting to nginx container... (type 'exit' to return)
docker compose -f docker-compose.yml exec nginx bash 2>nul
if errorlevel 1 docker compose -f docker-compose.wordpress.yml exec nginx bash
pause
goto menu

:shell_php
echo.
echo Connecting to PHP container... (type 'exit' to return)
docker compose -f docker-compose.yml exec php bash 2>nul
if errorlevel 1 docker compose -f docker-compose.wordpress.yml exec php bash
pause
goto menu

:stop_all
echo.
echo Stopping all demo containers...
docker compose -f docker-compose.yml down 2>nul
docker compose -f docker-compose.wordpress.yml down 2>nul
echo All stopped.
pause
goto menu

:unit_tests
echo.
echo Building and running unit tests...
docker build -t htaccess-test -f ..\Dockerfile ..
docker run --rm htaccess-test bash /tests/run_tests.sh
pause
goto menu

:end
exit /b 0
