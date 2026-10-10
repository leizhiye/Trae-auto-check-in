@echo off
title TraeWork auto Check in
echo Your language is what?
echo 1.Chinese
echo 2.English
set /p language= 
if "%language%"=="1" (
    (
        echo Initialization completed
        echo language=Chinese
    ) > .log
) else (
    if "%language%"=="2" (
        (
            echo Initialization completed
            echo language=English
        ) > .log
    ) else (
        echo what are you do bro???
        echo Is number,just 1 or 2...
    )
)

(
@echo off
echo node "TraeWork auto Check in.js"
echo pause
) > start.bat
cls
if "%language%"=="1" (
    echo 初始化已完成，现在请使用start.bat进行签到。（我绝对不会告诉你这个句号是我闲的没事加上去的）
) else (
    echo Initialization completed,please use the start.bat to check in.
)
pause
(goto) 2>nul & del /f /q "%~f0"