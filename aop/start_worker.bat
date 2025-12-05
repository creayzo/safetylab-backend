@echo off
REM Start Celery Worker for AOP (Windows)
REM
REM Usage:
REM   start_worker.bat [queue_name] [concurrency]
REM
REM Examples:
REM   start_worker.bat processing 4
REM   start_worker.bat wal_consumer 2
REM

set QUEUE=%1
if "%QUEUE%"=="" set QUEUE=processing,wal_consumer,forwarding,websocket

set CONCURRENCY=%2
if "%CONCURRENCY%"=="" set CONCURRENCY=4

set LOGLEVEL=%3
if "%LOGLEVEL%"=="" set LOGLEVEL=info

echo Starting Celery Worker...
echo Queue: %QUEUE%
echo Concurrency: %CONCURRENCY%
echo Log Level: %LOGLEVEL%
echo.

celery -A aop worker ^
    --queues=%QUEUE% ^
    --concurrency=%CONCURRENCY% ^
    --loglevel=%LOGLEVEL% ^
    --max-tasks-per-child=1000 ^
    --time-limit=300 ^
    --soft-time-limit=240 ^
    --pool=solo ^
    --hostname=worker@%%h

pause
