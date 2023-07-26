@ECHO OFF
REM INFO SYSTEMES
echo\
echo\
@ECHO [+] SYS INFO : [+] 
echo\
echo\
echo ---------------------------------------------------------------------------
systeminfo | findstr /B /C:"Nom de l" /C:"Nom du systäme d?exploitation" /C:"Version du systäme" /C:"Type du systäme" /C:"Correctif(s):"
echo ---------------------------------------------------------------------------
echo\
echo\
REM INFO SUR LE NOM DU DC/DOMAIN/USER  
@ECHO [+] DC/DOMAIN/USER : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
set | findstr /B /C:"LOGONSERVER" /C:"USERDNSDOMAIN" /C:"USERNAME"
echo ---------------------------------------------------------------------------
echo\
echo\
REM CONNECTED DRIVES 
@ECHO [+] TROUVER DES LECTEURS CONNECTêS : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
net use 
echo ---------------------------------------------------------------------------
echo\
echo\
REM LE USER
@ECHO [+] USER : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
echo %username%
whoami
echo ---------------------------------------------------------------------------
echo\
echo\
REM LES PRIVILEGES
@ECHO [+] LES PRIVILEGES : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
whoami /priv
echo ---------------------------------------------------------------------------
echo\
echo\
REM LES USERS SUR LE SYSTEM
@ECHO [+] LES AUTRES USERS DU SYSTEM : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
net users
echo ---------------------------------------------------------------------------
dir /b /ad "C:\Users\"
echo ---------------------------------------------------------------------------
echo\
echo\
REM USERS WINDOWS XP ET PLUS ANCIENS
@ECHO [+] USERS WINDOWS XP ET PLUS ANCIENS : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
dir /b /ad "C:\Documents and Settings\"
echo ---------------------------------------------------------------------------
echo\
echo\
REM Quelqu'un d'autre est-il connectÇ ?
@ECHO [+] QUELQUN'UN D'AUTRE EST-IL CONNECTê : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
qwinsta
echo ---------------------------------------------------------------------------
echo\
echo\
REM SYSTEM GROUPES 
@ECHO [+] SYSTEM GROUPES : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
net localgroup
echo ---------------------------------------------------------------------------
echo\
echo\
REM MEMBRES DU GROUP ADMINISTRATORS 
@ECHO [+] MEMBRES DU GROUP ADMINISTRATORS : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
net localgroup Administrators
echo ---------------------------------------------------------------------------
echo\
echo\
REM VERIFICATION MDP AUTOLOGON D'UN USER DANS LE REGISTRE
@ECHO [+] VERIFICATION DES MDP AUTOLOGON DANS LE REGISTRE : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
echo ---------------------------------------------------------------------------
echo\
echo\
REM VERIFICATION DES MDP DANS CREDENTIAL MANAGER
@ECHO [+] MDP DANS CREDENTIAL MANAGER : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
cmdkey /list
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
echo ---------------------------------------------------------------------------
echo\
echo\
REM VERIFICATION D'ACCESS A SAM ET SYSTEM
@ECHO [+] SAM ET SYSTEM ACCESS : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\repair\SAM
echo ---------------------------------------------------------------------------
echo\
echo\
REM VERIFICATION DES PERMISSIONS SUR LES DOSSIERS
@ECHO [+] AUTORISATION COMPLETE PR TT LE MONDE SUR LES DOSSIERS : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
echo ---------------------------------------------------------------------------
echo\
echo\
REM MODIFIER LES AUTORISATIONS PR TT LE MONDE SUR DES DOSSIERS OU PROGRAMES
@ECHO [+] MODIFCATIONS PR TT LE MONDE SUR LES PROGRAMMES OU DOSSIERS : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users"
echo ---------------------------------------------------------------------------
echo\
echo\
REM TELECHARGE ACCESSCHK ET CHECKER LES DOSSIERS MODIFIABLES
@ECHO [+] CHECKER LES DOSSIERS MODIFIABLES : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
accesschk.exe -nobanner /accepteula -qwsu "Everyone" *
accesschk.exe -nobanner /accepteula -qwsu "Authenticated Users" *
accesschk.exe -nobanner /accepteula -qwsu "Users" *
echo ---------------------------------------------------------------------------
echo\
echo\
REM TELECHARGE ACCESSCHK ET CHECKER LES SERVICES MODIFIABLES
@ECHO [+] CHECKER LES SERVICES MODIFIABLES : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
accesschk.exe -nobanner /accepteula -uwcqv "Everyone" *
accesschk.exe -nobanner /accepteula -uwcqv "Authenticated Users" *
accesschk.exe -nobanner /accepteula -uwcqv "Users" *
echo ---------------------------------------------------------------------------
echo\
echo\
REM UNQUOTED SERVICE PATH
@ECHO [+] CHECKER LES UNQUOTED SERVICE PATH : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
wmic service get name,displayname,pathname,startmode 2>nul |findstr /i "Auto" 2>nul |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """
echo ---------------------------------------------------------------------------
echo\
echo\
REM QUELLES SONT LES T∂CHES PROGRAMMEES ? 
@ECHO [+] TéCHES PROGRAMMEES : [+]
echo\
echo\
echo ---------------------------------------------------------------------------
schtasks /query /fo LIST 2>nul | findstr TaskName
dir /B C:\windows\tasks
echo ---------------------------------------------------------------------------
echo\
echo\



REM LES PROCCESSUS ET SERVICES EN COURS D'EXECUSSION
REM @ECHO [+] PROCCESSUS ET SERVICES EN COURS D'EXECUSSION : [+]
REM echo\
REM echo\
REM echo ---------------------------------------------------------------------------
REM tasklist /svc
REM tasklist /v
REM echo ---------------------------------------------------------------------------
REM echo\
REM echo\
REM @ECHO [+] LES LOGICIELS INSTALLêS : [+]
REM echo\
REM echo\
REM echo ---------------------------------------------------------------------------
REM reg query HKEY_LOCAL_MACHINE\SOFTWARE
REM echo ---------------------------------------------------------------------------
REM echo ---------------------------------------------------------------------------
REM dir /a "C:\Program Files (x86)"
REM echo ---------------------------------------------------------------------------
REM echo ---------------------------------------------------------------------------
REM dir /a "C:\Program Files"
REM echo ---------------------------------------------------------------------------
REM echo\
REM echo\
REM @ECHO [+] Network : [+]
REM echo\
REM echo\
REM echo ---------------------------------------------------------------------------
REM ipconfig /all | findstr /C:" Adresse IPv4"
REM echo ---------------------------------------------------------------------------
REM echo\
REM echo\
REM echo ---------------------------------------------------------------------------
REM route print 
REM echo ---------------------------------------------------------------------------
REM echo\
REM echo\
REM echo ---------------------------------------------------------------------------
REM netstat -ano | findstr /C:"LISTENING" /C:"0.0.0.0:0" /C:"0.0.0.0:"
REM echo ---------------------------------------------------------------------------













PAUSE