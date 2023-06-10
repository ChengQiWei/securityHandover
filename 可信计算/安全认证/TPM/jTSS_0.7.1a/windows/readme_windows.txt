                         IAIK jTSS Core Services Setup

   This will setup and install the jTSS Core Services as system service. It
   enables Java applications to access the Trusted Platform Module (TPM). The
   IAIK jTSS is an implementation of the TCG Software Stack for the Java(tm)
   programming language. A TCG Software Stack, as specified by the Trusted
   Computing Group, is one of the main software building blocks of a Trusted
   Computing enhanced system.

   Please see [1]http://trustedjava.sf.net for downloads, further
   documentation and support.

1. Installation Guide

   jTSS comes with a fully automatic installer for the jTSS Core Services for
   Windows. This will enable your applications to access the TPM via
   jTSS/TCS.

   Before you install jTSS check if the TPM was detected. In order to do
   that:

     * Open Microsoft Management Consol mmc.exe

     * Add a new Snap-in Ctrl+M where you choose TPM Management

   Setup automatically tests for the following requirements:

     * Windows Vista, Windows 7, Windows Server 2008, 32 or 64 bit

     * Administrator privileges

     * Sun Java JRE 1.5, 1.6, or 1.7 installed, 32 or 64 bit

     * TPM Enabled and TBS active

   Start setup.exe to install jTSS. You’ll need to agree to the license terms
   before you continue. In the setup progress you can choose where to install
   jTSS (default: C:\Program Files\jTSS). After installing the files the TCS
   core services will be started automatically. Additionally you can start a
   test at the end of the installation progress. With the test you will get a
   pop up window which tells you if the connection with the TCS services and
   the TPM works as desired or not.

   If the test was successful you are able to use jTSS Core services! Your
   Java application may either choose to use the TSP library with the default
   configuration provided in the installation directory or to ship with its
   own copy and configuration files (this is recommended).

   Note: The test may fail, if the JRE is not included in the Windows PATH
   variable.

2. License Terms

   Please read the following licence terms carefully and only perfom the
   installation if you agree to them.

   Copyright (c) IAIK, Graz University of Technology, 2010. All rights
   reserved.

   IAIK jTSS is released under a dual licensing model:

     * For Open Source development, IAIK jTSS is licensed under the terms of
       the GNU GPL version 2. The full text of the GNU GPL v2 is shipped with
       the product or can be found online at ([2]GPL).

     * In all other cases, the "Stiftung SIC Java (tm) Crypto-Software
       Development Kit Licence Agreement" applies. The full license text can
       be found online at [3]Stiftung SIC.

   Optional components of jTSS depend on a number of third party libraries
   ("external libraries") which come under different licenses.

   For convenience, the jTSS deployment packages ships with an aggregate of
   external libraries with individual, cost free or open source licences. You
   need to agree to these individual licenses if you use advanced jTSS
   features (SOAP, system daemon or service, persistent key database, windows
   installer or the .deb package).

   In the following, we list which external libraries are required by some
   components of jTSS. We also refer to the the original download site and
   specify the licenses that cover those components. All those files and the
   license texts are also found in the ext_libs folder.

    1. JavaBeans Activation Framework Version 1.1.1

            Download

                    [4]Sun JavaBeans

            License

                    [5]Sun JavaBeans License

            Contains

                    activation.jar

    2. Axis Version 1.4 final

            Download

                    [6]Apache Axis

            License

                    [7]Apache Axis License Version 2

            Contains

                    axis-ant.jar
                    axis.jar
                    commons-discovery-0.2.jar
                    commons-logging-1.0.4.jar
                    jaxrpc.jar
                    log4j-1.2.8.jar
                    saaj.jar
                    wsdl4j-1.5.1.jar

    3. Commons Daemon Version 1.0.5

            Download

                    [8]Apache Daemon

            License

                    [9]Apache Daemon License Version 2

            Contains

                    commons-daemon.jar

    4. JavaMail API Version 1.4.1

            Download

                    [10]Sun JavaMail

            License

                    [11]COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL)

            Contains

                    mail.jar

    5. Microsoft Visual C++ Runtime Redistributable 2008 (x86 and x64)
       (Windows only)

            Download

                    [12]http://www.microsoft.com/downloads

            User License

                    vc_redist_eula.txt (Redistributed for jTSS under Vistual
                    Studio 2008 licence)

            Contains

                    vcredist_x86.exe
                    vcredist_x64.exe

   The following external libraries are required to use jTSS with the
   database implementation of Persistent Storage:

    1. HSQL Licence

            Download

                    [13]HSQL - 100% Java Database

            License

                    [14]ORIGINAL LICENSE (a.k.a. "hypersonic_lic.txt")

            Contains

                    hsqldbmin.jar

   The setup.exe Installer is created with Innosetup (Windows only).

    1. Inno Setup License

            Download

                    [15]Inno Setup

            License

                    [16]Inno Setup License

            Contains

                    setup.exe (installer code only)

   --------------------------------------------------------------------------

   Last updated 2010-09-22 14:52:27 CEST

References

   Visible links
   1. http://trustedjava.sf.net/
   2. http://www.gnu.org/licenses/gpl.html
   3. http://jce.iaik.tugraz.at/sic/sales/licences/commercial
   4. http://java.sun.com/products/javabeans/jaf/downloads/index.html
   5. http://developers.sun.com/license/berkeley_license.html
   6. http://ws.apache.org/axis/
   7. http://commons.apache.org/license.html
   8. http://commons.apache.org/downloads/download_daemon.cgi
   9. http://commons.apache.org/license.html
  10. http://java.sun.com/products/javamail/
  11. http://www.opensource.org/licenses/cddl1.php
  12. http://www.microsoft.com/downloads/details.aspx?familyid=200b2fd9-ae1a-4a14-984d-389c36f85647&displaylang=en
  13. http://hsqldb.org/
  14. http://hsqldb.org/web/hsqlLicense.html
  15. http://www.innosetup.com/isinfo.php
  16. http://www.innosetup.com/files/is/license.txt
