@echo off
echo SAINT Security Suite - تثبيت المتطلبات
echo ====================================
echo.

REM التحقق من وجود Python
python --version > nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] خطأ: Python غير مثبت أو غير موجود في متغير PATH.
    echo [!] يرجى تثبيت Python 3.6 أو أحدث من https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

REM التحقق من إصدار Python
for /f "tokens=2" %%I in ('python --version 2^>^&1') do set PYTHON_VERSION=%%I
echo [+] تم العثور على Python %PYTHON_VERSION%

REM تثبيت المتطلبات
echo [+] جاري تثبيت المكتبات المطلوبة...
echo.
python -m pip install --upgrade pip
python -m pip install -r requirements_saint.txt

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] حدث خطأ أثناء تثبيت المكتبات.
    echo [!] يرجى التحقق من اتصالك بالإنترنت والمحاولة مرة أخرى.
) else (
    echo.
    echo [+] تم تثبيت جميع المكتبات بنجاح!
    echo [+] يمكنك الآن استخدام SAINT Security Suite.
    echo [+] للمساعدة، قم بتشغيل: python saint.py --help
)

echo.
pause