@echo off
rem
rem Copyright (C) 2008 IAIK, Graz University of Technology
rem
rem This script starts the jTSS Core Services as a Windows Service. 
rem Further it provides functions to restart, stop, and remove the Windows 
rem Service.  

rem determine the location of this script
rem set DIR="%~dp0"
rem first get the short path of this file and then remove the filename
SET DIR=%~s0
SET DIR=%DIR:~0,-11%

rem x86 prunserv need 32-bit JVM, amd64 prunserv needs 64 bit JVM
set EXECUTABLE=%DIR%..\ext_libs\x86\prunsrv.exe
set SERVICE=tcsdaemon
set README=%DIR%\jtss_readme.txt

set LOGDIR=%DIR%..\log
set EXTLIBPATH=%DIR%..\ext_libs
set LIBPATH=%DIR%..\lib

set CLASSPATH_SOAP=%EXTLIBPATH%\activation.jar
set CLASSPATH_SOAP=%EXTLIBPATH%\axis-ant.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%EXTLIBPATH%\axis.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%EXTLIBPATH%\commons-daemon.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%EXTLIBPATH%\commons-discovery-0.2.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%EXTLIBPATH%\commons-logging-1.0.4.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%EXTLIBPATH%\jaxrpc.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%EXTLIBPATH%\log4j-1.2.8.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%EXTLIBPATH%\mail.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%EXTLIBPATH%\saaj.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%EXTLIBPATH%\wsdl4j-1.5.1.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%EXTLIBPATH%\xerces.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%EXTLIBPATH%\junit.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%EXTLIBPATH%\hsqldbmin.jar;%CLASSPATH_SOAP%

set CLASSPATH_SOAP=%LIBPATH%\iaik_jtss_tcs.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%LIBPATH%\iaik_jtss_tcs_soap.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%LIBPATH%\iaik_jtss_tsp.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%LIBPATH%\iaik_jtss_tsp_soap.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=%LIBPATH%\iaik_jtss_tsp_tests.jar;%CLASSPATH_SOAP%
set CLASSPATH_SOAP=.;%CLASSPATH_SOAP%

rem Just allow one paramter. Otherwise return README
rem Use "start" if no paramters are provided

if NOT EXIST %LIBPATH%\iaik_jtss_tcs.jar      goto libsnotfound
if NOT EXIST %LIBPATH%\iaik_jtss_tsp.jar      goto libsnotfound
if NOT EXIST %LIBPATH%\iaik_jtss_tcs_soap.jar goto soaplibsnotfound
if NOT EXIST %LIBPATH%\iaik_jtss_tsp_soap.jar goto soaplibsnotfound
rem if NOT EXIST %EXECUTABLE goto prunsrvnotfound

rem check for sufficient privileges
%WINDIR%\System32\whoami /groups | %WINDIR%\System32\find "S-1-5-32-544" > nul
if errorlevel 1 goto notadmin


if "%2" NEQ "" goto help

if "%1" EQU ""        goto start  
if "%1" EQU "start"   goto start
if "%1" EQU "restart" goto restart
if "%1" EQU "remove"  goto remove
if "%1" EQU "install"   goto install


if "%1" EQU "stop" ( 
  goto stop  
)else (
  goto help
)

:help
more %README%
goto end

:stop
echo Stopping IAIK jTSS Core Services...
net stop %SERVICE%
goto end

:remove
echo REMOVE
%EXECUTABLE% //DS//%SERVICE%
goto end

:restart
echo Restarting IAIK jTSS Core Services...
%EXECUTABLE% //DS//%SERVICE%
goto start

if not errorlevel 0 goto secondlaunch


:install
echo Installing IAIK jTSS Core Services 32-bit...
if NOT EXIST %LOGDIR% md %LOGDIR%

rem try 32-bit version first
%EXECUTABLE% //IS//%SERVICE%^
 --Description="IAIK jTSS Core Services"^
 --LogPath=%LOGDIR%^
 --Startup=auto^
 --StartPath=%DIR%\^
 --LogLevel=Debug^
 --StdOutput=%LOGDIR%\out.txt^
 --StdError=%LOGDIR%\err.txt^
 --Jvm=auto^
 ++JvmOptions=-Djtss.tsp.ini.file="%LIBPATH%\ini\jtss_tsp.ini"^
 ++JvmOptions=-Djtss.tcs.ini.file="%LIBPATH%\ini\jtss_tcs.ini"^
 --Classpath=%CLASSPATH_SOAP%^
 --DisplayName="TCSDaemon"^
 --StartMode=jvm^
 --StartClass=iaik.tc.tss.impl.java.tcs.soapservice.server.StartAxisServerWindows^
 --StopMode=jvm^
 --StopClass=iaik.tc.tss.impl.java.tcs.soapservice.server.StartAxisServerWindows^
 --StopMethod=shutdown^
 --StopTimeout=10

net start %SERVICE%

if %errorlevel% == 0 goto end
echo Failed. Attempt installing IAIK jTSS Core Services 64-bit...

rem remove 32-bit version
%EXECUTABLE% //DS//%SERVICE%

rem switch over to 64-bits
set EXECUTABLE=%DIR%..\ext_libs\amd64\prunsrv.exe
%EXECUTABLE% //IS//%SERVICE%^
 --Description="IAIK jTSS Core Services"^
 --LogPath=%LOGDIR%^
 --Startup=auto^
 --StartPath=%DIR%\^
 --LogLevel=Debug^
 --StdOutput=%LOGDIR%\out.txt^
 --StdError=%LOGDIR%\err.txt^
 --Jvm=auto^
 ++JvmOptions=-Djtss.tsp.ini.file="%LIBPATH%\ini\jtss_tsp.ini"^
 ++JvmOptions=-Djtss.tcs.ini.file="%LIBPATH%\ini\jtss_tcs.ini"^
 --Classpath=%CLASSPATH_SOAP%^
 --DisplayName="TCSDaemon"^
 --StartMode=jvm^
 --StartClass=iaik.tc.tss.impl.java.tcs.soapservice.server.StartAxisServerWindows^
 --StopMode=jvm^
 --StopClass=iaik.tc.tss.impl.java.tcs.soapservice.server.StartAxisServerWindows^
 --StopMethod=shutdown^
 --StopTimeout=10
net start %SERVICE%
goto end


:start
echo Starting IAIK jTSS Core Services...

if NOT EXIST %LOGDIR% md %LOGDIR%

%EXECUTABLE% //IS//%SERVICE%^
 --Description="IAIK jTSS Core Services"^
 --LogPath=%LOGDIR%^
 --Startup=auto^
 --StartPath=%DIR%\^
 --LogLevel=Debug^
 --StdOutput=%LOGDIR%\out.txt^
 --StdError=%LOGDIR%\err.txt^
 --Jvm=auto^
 ++JvmOptions=-Djtss.tsp.ini.file="%LIBPATH%\ini\jtss_tsp.ini"^
 ++JvmOptions=-Djtss.tcs.ini.file="%LIBPATH%\ini\jtss_tcs.ini"^
 --Classpath=%CLASSPATH_SOAP%^
 --DisplayName="TCSDaemon"^
 --StartMode=jvm^
 --StartClass=iaik.tc.tss.impl.java.tcs.soapservice.server.StartAxisServerWindows^
 --StopMode=jvm^
 --StopClass=iaik.tc.tss.impl.java.tcs.soapservice.server.StartAxisServerWindows^
 --StopMethod=shutdown^
 --StopTimeout=10
net start %SERVICE%
goto end

:secondlaunch
set EXECUTABLE=%DIR%..\ext_libs\x86\prunsrv.exe

:libsnotfound
echo Could not find the jTSS Libraries
goto end

:soaplibsnotfound
echo Could not find the SOAP support for the jTSS Libraries
goto end

:prunsrvnotfound
echo Could not find prunsrv.exe
goto end

:notadmin
echo You need admin privileges to start or stop the TCS
goto end

:end
