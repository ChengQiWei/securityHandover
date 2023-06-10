echo off
setlocal

rem
rem Copyright (C) 2008 IAIK, Graz University of Technology
rem

rem determine the location of this script
rem first get the short path of this file and then remove the filename
SET DIR=%~s0
SET DIR=%DIR:~0,-12%

rem SET DIR=%~dp0

set LIBPATH=%DIR%\..\lib
set EXTLIBPATH=%DIR%\..\ext_libs

set CLASSPATH=%EXTLIBPATH%\activation.jar
set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\axis-ant.jar
set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\axis.jar
set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\commons-daemon.jar
set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\commons-discovery-0.2.jar
set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\commons-logging-1.0.4.jar
set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\jaxrpc.jar
set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\log4j-1.2.8.jar
set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\mail.jar
set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\saaj.jar
set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\wsdl4j-1.5.1.jar
set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\xerces.jar

set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\junit.jar
set CLASSPATH=%CLASSPATH%;%EXTLIBPATH%\hsqldbmin.jar

set CLASSPATH=%CLASSPATH%;%LIBPATH%\iaik_jtss_tcs.jar
set CLASSPATH=%CLASSPATH%;%LIBPATH%\iaik_jtss_tcs_soap.jar
set CLASSPATH=%CLASSPATH%;%LIBPATH%\iaik_jtss_tsp.jar
set CLASSPATH=%CLASSPATH%;%LIBPATH%\iaik_jtss_tsp_soap.jar
set CLASSPATH=%CLASSPATH%;%DIR%\iaik_jtss_tsp_tests.jar
set CLASSPATH=.;%CLASSPATH%

java -cp %CLASSPATH% iaik.tc.tss.test.tsp.java.simple.TestMain 
