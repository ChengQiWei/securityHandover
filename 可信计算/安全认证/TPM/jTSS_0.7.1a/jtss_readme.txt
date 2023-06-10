           IAIK jTSS - TCG Software Stack for the Java (tm) Platform

   0.7.1a

   Ronald Toegl <rtoegl_iaik@users.sourceforge.net>
   Thomas Winkler
   Michael E. Steurer
   Martin Pirker <mpirker_iaik@users.sourceforge.net>
   Christian Pointner
   Thomas Holzmann
   Michael Gissing
   Josef Sabongui
   Robert Stoegbuchner

1. Introduction

   The IAIK jTSS stack is an implementation of the TCG Software Stack for the
   Java (tm) programming language. In contrast to approaches like the
   IAIK/OpenTC jTSS Wrapper, the IAIK jTSS does not wrap a C stack like
   TrouSerS but implements all layers in Java (tm).

   A TCG Software Stack, as specified by the Trusted Computing Group
   ([1]TCG), is one of the main software building blocks of a Trusted
   Computing enhanced system.

   Development of the IAIK jTSS was supported by the European Commission as
   part of the OpenTC project (Ref. Nr. 027635) and by the Austrian FIT-IT
   Trust in IT Systems programme in project acTvSM [2]acTvSM and is supported
   by the European Commission as part of the STANCE project (Ref. Nr.
   317753).

   The IAIK jTSS is developed and maintained at the Institute for Applied
   Information Processing and Communication (Institut fuer Angewandte
   Informationsverarbeitung und Kommunikation, [3]IAIK) at Graz University of
   Technology ([4]TU Graz).

  1.1. A Word of Caution

   Development of IAIK jTSS is still not complete. It currently is regarded
   as experimental software targeted at research and educational
   environments. Use the software at your own risk!

  1.2. License

   Copyright (c) IAIK, Graz University of Technology, 2010. All rights
   reserved.

   IAIK jTSS is released under a dual licensing model:

     * For Open Source development, IAIK jTSS is licensed under the terms of
       the GNU GPL version 2. The full text of the GNU GPL v2 is shipped with
       the product or can be found online at ([5]GPL).

     * In all other cases, the "Stiftung SIC Java (tm) Crypto-Software
       Development Kit Licence Agreement" applies. The full license text can
       be found online at [6]Stiftung SIC. For pricing and further
       information please contact jce-sales@iaik.at.

   Optional components of jTSS depend on a number of third party libraries
   ("external libraries") which come under different licenses.

2. Current Status

   As mentioned in earlier sections, the IAIK jTSS still is in early stages
   of development and therefore is not yet feature complete nor exhaustively
   tested.

   For development, the following TPMs have been used:

     * Infineon 1.2 TPM

     * TPM Emulator from ETH Zurich (Software)

     * Atmel 1.2 TPM

     * Intel Series 4 chipset (Q45) integrated 1.2 TPM

   These TPMs have also been used for development or are reported to be
   compatible:

     * Infineon 1.1b TPM

     * Broadcom 1.2 TPM

     * ST Microelectronics 1.2 TPM

     * Atmel 1.1 TPM (limited)

     * IBM Software TPM 1.2

   Although all TPMs are based on the TCG TPM specification, some TPM models
   might behave a little different from other TPMs. The IAIK jTSS tries to
   abstract all these little twists and provide a consistent behavior to
   applications regardless of the actual underlying hardware TPM. In some
   cases however IAIK jTSS might fail on a TPM. To further enhance IAIK jTSS
   we rely on your feedback and potential contributions.

   Due to the fact that IAIK jTSS is fully implemented in Java (tm), porting
   it to different operating systems becomes relatively easy. Currently, the
   following systems are supported:

     * Linux (using TPM device drivers of recent 2.6 kernels)

     * Microsoft Windows Vista or higher (using TPM Base Services)

   Regarding TSS features, IAIK jTSS covers large parts of the TSS 1.1
   specification and considerable parts of the 1.2 TSS specification. TPMs of
   version 1.2 are fully supported regarding their changes in resource
   management.

  2.1. Features Currently Supported by IAIK jTSS

   TSS Device Driver Library (TDDL)

   The TDDL API is targeted towards C applications, so instead we implement

     * Linux support by accessing TPM device file and

     * Windows Vista support by accessing Microsoft TPM Base Services
       ([7]TBS).

   TSS Core Services (TCS)

     * Parameter Block Generator (PBG) covering all 1.2 TPM functions

     * C structure parser covering all 1.2 TPM structures

     * Authorization Manager (TPM 1.1 and 1.2 support)

     * Key Cache Manager (TPM 1.1 and 1.2 support)

     * Event Manager

     * Persistent System Storage

     * TCS Interface (TCSI) layer

     * TCS system service with SOAP interface

     * Monotonic Counters

   TSS Service Provider (TSP)

     * TPM command authorization (OIAP, OSAP, …) and validation component

     * TSS Service Provider Interface (TSPI) modified for Java use

     * Attribute Functions (Get/SetAttrib)

     * TPM (AIK creation, ownership, capabilities, event log, status, random
       data, quote, PCR extend, …)

     * TSP Context (context management, object creation, selected PS
       functionality, …)

     * Encrypted Data (Bind/Unbind, Seal/Unseal)

     * Hash (hash computation, signature verification, …)

     * RSA key (creation, loading, extracting, …)

     * Key certification

     * PcrComposite (selection, setting and getting PCRs including 1.2
       features like locality, …)

     * Policy (creating, managing and assigning policies)

     * Time Stamping (TPM 1.2 only)

     * NV Storage read access (TPM 1.2 only)

     * SOAP interface

     * Key Migration (partially) and CMKs (TPM 1.2 only)

     * NV Storage (TPM 1.2 only)

     * Monotonic Counters (read) (TPM 1.2 only)

     * Revocable EKs and late EK creation (TPM 1.2 only)

  2.2. TSS Specified Features not included in this Release

     * Delegation

     * TPM Maintenance (vendor specific)

     * Direct Anonymous Attestation (DAA)

     * Transport Sessions

     * TSS_SECRET_MODE_NONE is currently not supported by IAIK jTSS. That
       means that e.g. key objects can not be created without specifying a
       secret. To work around this issue you can use the
       TSS_WELL_KNOWN_SECRET as the entity secret in such cases.

3. Requirements

  3.1. Java (tm) Environment

   To use the IAIK jTSS you need to have a Sun Java (tm) Environment of
   version 5 or later. Earlier Java (tm) versions do not provide the required
   cryptographic functionality. Compatibility with other Java vendors is
   unknown and untested.

  3.2. JCE Unlimited Strength Jurisdiction Policy Files

   To make full use of the cryptographic capabilities of the Java
   Cryptography Extension (JCE), the Unlimited Strength Jurisdiction Policy
   Files have to be installed. Download the JCE Unlimited Strength
   Jurisdiction Policy Files([8]JCE) and follow the instructions.This is a
   requirement for the TSS to be able to handle TPM RSA keys. In case you
   experience errors like "Illegal key size or default parameters" chances
   are high that these policy files are not (or not correctly) installed.

  3.3. Hardware TPM or TPM Emulator for Linux

   To make use of IAIK jTSS you require either a hardware TPM or the TPM
   emulator from ETH Zurich [9]TPM Emulator.

   The TPM emulator is a software package for Linux operating systems
   providing TPM functionality as a pure software implementation. It is
   especially useful for testing and development on systems where no hardware
   TPM is available. The emulator consists of a Linux kernel module and a
   user space daemon implementing the actual TPM functionality. For details
   on how to set up and configure the TPM emulator please consult the
   documentation that is included in the emulator package. Note that the time
   stamping is not working correctly in TPM emulator 0.5 or earlier.

   In case you have a hardware TPM, you have to ensure that a proper Linux
   kernel driver for your TPM is loaded. Recent 2.6 kernels come with drivers
   for all major TPM manufacturers. For 1.2 TPMs, the TIS driver might be the
   way of choice to access your TPM.

   No matter if you are using a hardware TPM or the TPM emulator, a device
   file called /dev/tpm (or /dev/tpmX) will show up. If you do not have this
   file, the TPM can not be accessed by the TSS.

  3.4. Microsoft Windows Vista and higher

   The IAIK jTSS also includes support for Microsoft Windows Vista (32-bit
   and 64-bit), Server 2008 and Windows 7. In this case the TPM is accessed
   via the TPM Base Services ([10]TBS) of Vista. The TBS provides a very thin
   abstraction layer for TPM access. By default, Vista only comes with
   support for 1.2 TPMs. If your TPM is supported by Vista and if it can be
   accessed via the TBS, the IAIK jTSS should be able to communicate with
   your TPM on Vista systems.

   Note that the default configuration of Vista blocks some TPM commands at
   the TBS level. Among these are commands for quoting and PCR access. You
   have to use the group policy editor to unblock this functions. To unblock
   these commands, run the Group Policy Editor: gpedit.msc | Computer
   Configuration | Administrative Templates | System | Trusted Platform
   Module Services | Ignore the default list of blocked TPM commands =
   enabled For details please refer to the Microsoft Technet ([11]Vista TPM
   Functions).

   Support for Vista 64-bit, Windows Server 2008 or Windows 7 is
   experimental.

4. Setup and Usage

   If you use a hardware TPM you first have to activate it in your BIOS. Look
   into the manual of your computer to find out how to do that.

  4.1. Manual Setup for Linux and Windows

   There are two ways to operate the IAIK jTSS:

     * With local bindings, the TSP layer directly calls the TCS methods.
       This is well suited for development, experimenting and debugging. As a
       drawback, the Java VM must have proper access rights to the TPM
       device. We recommend you to use this to gain initial experience with
       IAIK jTSS.

     * With SOAP bindings, the TSP will call the TCS via a web service
       interface. The TCS will run as system service (daemon). Once
       installed, any unprivileged application can access it.

   In this chapter we discuss how to use the local bindings. You will find a
   detailed documentation on the SOAP bindings further below.

   IAIK jTSS comes in pre-compiled form. In the lib subdirectory, you will
   find four jar libraries:

     * iaik_jtss_tsp.jar This is the TSS Service Provicer (TSP) library you
       have to include in the classpath of your Java (tm) applications to
       make use of the TPM. The TSP library provides the programming API to
       be used in applications when interacting with the TPM.

     * iaik_jtss_tsp_soap.jar The library that provides the SOAP support for
       the TSP.

     * iaik_jtss_tcs.jar This library contains the TSS Core Services (TCS).
       Typically, the TCS would run as an independent system service.
       Alternatively it can be linked to your TC aware application just like
       the TSP library. Note that all TPM interaction is done via the TSP
       library.The TCS is not designed to be used directly in your
       applications.

     * iaik_jtss_tcs_soap.jar The library that provides the SOAP support for
       the TCS.

   By default jTSS is using standard configurations. If you don’t agree with
   this settings, a few basic settings need to be configured in jtss_tcs.ini
   and jtss_tsp.ini respectively. To do that read the comments in the .ini
   files carefully and uncomment or fill in the right settings. The .ini
   files must reside in the same directory as the corresponding library file,
   or in another location specified in the jtss.tsp.ini.file respectively
   jtss.tcs.ini.file Java properties. For both libraries the persistent
   storage and the event log has to be configured. Details are given in the
   Technical Documentation section. In addition, the binding interface
   between TSP and TCS must be set. The default are local bindings with the
   type set to iaik.tc.tss.impl.java.tsp.TcTssLocalCallFactory. if you wish
   to use the SOAP interface, set it to
   iaik.tc.tss.impl.java.tsp.TcTssSOAPCallFactory. Additionally, it is
   possible to configure which TPM device to use.

   Aside from linking these jar libraries to your TC aware application (which
   essentially means adding them to the classpath) and the optional
   configuration of the .ini files, there are no further setup steps
   required.

   In the src subdirectory you can find the entire source code of IAIK jTSS.
   Details on the organization of the source code are given in the Technical
   Documentation section.

    4.1.1. Test the TCS TSP communication under Linux

   You can test the TCS implementation with:

   user@localhost:jTSS$ sudo bash tests/run_tests.sh

   Execute this test as root or adapt the access permissions to the TPM
   device if you use local bindings.

    4.1.2. Test the TCS TSP communication under Windows Vista

   You can test the TCS implementation with:

   c:\>jTSS> tests\run_tests.cmd -o your_tpm_ownersecret

   Execute this test from a command prompt with elevated administrative
   privileges if you use local bindings.

  4.2. Automatic Core Services Setup for Windows

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

  4.3. Core Services Installation as System Daemon in Linux

   IAIK jTSS now offers an experimental installation package for Debian Linux
   and derivate distributions like Ubuntu. The package is available in the
   deb folder and you can install it as follows.

   How to manually install the jtss_*_all.deb.deb package:

     * Dependencies: We use the Apache Commons Daemon Java library. In
       Ubuntu, these libraries are called jsvc and libcommons-daemon-java and
       you can install them with the package manager, i.e. synaptic, apt-get
       or aptitude.

     * From the terminal change into the deb directory of jTSS.

     * type sudo dpkg -i jtss_*_all.deb (replacing * with the version of the
       package)

   If you did not install the aforementioned dependencies prior to installing
   jtss you should see an error message like this:

 dpkg: dependency problems prevent configuration of jtss:
  jtss depends on jsvc; however:
   Package jsvc is not installed.
 dpkg: error processing jtss (--install):
  dependency problems - leaving unconfigured
 Errors were encountered while processing:
  jtss

   To correct the situation the command sudo apt-get -f install should
   suffice.

   The installer creates a user jtss in group tss with access priviledges to
   the TPM devices. The daemon can be controled via sudo /etc/init.d/jtss
   start|stop|restart. The log file will be kept in /var/log/jtss/eventlog,
   keys will be stored in /var/lib/jtss and the jar files will reside in
   /usr/share/jtss/lib.

   Note that this package contains an aggregate of third party libraries.

5. API Documentations and Sample Code

   To get an overview of the concepts and the general API usage of a TSS it
   is recommended to consult the [12]TSS Specification. Additionally, the
   IAIK jTSS comes with a JavaDoc API documentation located in the doc
   subfolder. This documentation comes in two different flavours: The
   javadoc_all directory contains the JavaDoc for the entire IAIK jTSS. For
   developers that are only using the TSP layer and its highlevel API, the
   javadoc_tsp contains all relevant information. This documentation tree is
   a subset of the javadoc_all tree. It covers the TSP level API that is
   meant to be used by application developers.

   Additionally to the provided JavaDoc, some example code demonstrating the
   basic usage of IAIK jTSS is included in the src/jtss_tsp/src_tests
   subfolder. It contains a set of jUnit test cases which can be used as a
   basis for own developments. Three short tests in the
   iaik.tc.tss.test.tsp.java.simple packet might provide the best entry to
   start with. For the implementation, a context object serves as entry point
   to all functionality such as authorized and validated TPM commands, policy
   and key handling, data hashing, encryption, and PCR composition.

   A precompiled version of this test code is located in the tests subfolder.
   A shell script to run the tests is included.

6. Technical Documentation

   This section provides a brief overview of technical aspects of IAIK jTSS.

  6.1. Architecture Overview

   Conforming with the TCG TSS specification, IAIK jTSS consists of two major
   parts: The TSP and the TCS. The TSP library is the entity that provides
   application developers with an API that allows access to all the TPM
   functions. The TSP is designed to be linked to an application that wants
   to make use of a TPM. The TCS is intended to be the only entity that
   directly accesses the TPM. As a consequence, the TCS is meant to be
   implemented as a system service or daemon. It is responsible for creating
   the TPM command streams, TPM command serialization, TPM resource
   management, event log management and the system persistent storage.

  6.2. Source Code Overview

   The source code of IAIK jTSS is split into three parts:

   TSS Service Provider (TSP)

   As mentioned in previous sections, the TSP is the part that provides
   application developers with an API for accessing TPM functionality. In
   IAIK jTSS the API part is defined as a set of interfaces located in the
   iaik.tc.tss.api package. The iaik.tc.tss.impl package holds the actual
   implementations of the interfaces defined in the api package. The impl
   package holds sub packages containing different types of TSP
   implementations. The java sub package e.g. contains a TSP completely
   written in Java (tm). Other sub packages could e.g. contain
   implementations such as a JNI implementation that interfaces a TSP written
   in C like the TrouSerS TSS. The key benefit of having split the API and
   the implementation is that the applications developed on top of the TSP
   can easily be switched from one underlying TSP implementation to another
   by simply changing the factory that creates TSP level objects.

   The layout of the TSP API package is like this:

     * iaik.tc.tss.api.tspi - contains the object oriented TSP interface of
       IAIK jTSS derived from the TSS specification. The package contains
       interfaces for all the object types like Context, TPM, RsaKey, Hash or
       EncData defined in the TSS spec.

     * iaik.tc.tss.api.structs.tsp - contains TSP level data structures as
       defined by the TSS spec

     * iaik.tc.tss.api.exceptions.tsp - contains TSP level exceptions

     * iaik.tc.tss.api.constants.tsp - contains TSP level constants and error
       codes

   TSS Core Services (TCS)

   The TCS is the component that directly interacts with the TPM. In a
   typical TSS implementation, this component is a daemon or system service.
   The current implementation of the IAIK jTSS features to let the TCS run as
   a daemon/system service as well as to access it as a library.

   The layout of the TCS package is as follows:

     * iaik.tc.tss.impl.java.tcs.authmgr - This package contains the
       authorization manager component. It is responsible for the management
       of TPM authorized sessions (caching and authorized session swapping).
       It contains implementations for different TPM types and operating
       systems. These implementations are derived from a common base class.
       The actual implementation is selected based upon the systems TPM and
       OS version.

     * iaik.tc.tss.impl.java.tcs.credmgr - The credential manager contained
       in this package contains all functions related to credentials, e.g.
       extracting credentials from IFX TPMs or the MakeIdentity function.

     * iaik.tc.tss.impl.java.tcs.ctxmgr - This package contains the TCS
       context manager. The purpose of this component is to keep track of
       established TCS contexts.

     * iaik.tc.tss.impl.java.tcs.eventmgr - This package contains the event
       manager component of the TCS. The event manager is responsible for
       storing and managing TSS event log entries.

     * iaik.tc.tss.impl.java.tcs.kcmgr - This package contains the key cache
       manager. Some TPM implementations support key swapping in case the TPM
       key slots are depleted. The package contains implementations for
       different TPM versions. Additionally, this package holds code that
       manages all operations involving TPM keys. This includes the
       translation of TCS level key handles to TPM level key handles.

     * iaik.tc.tss.impl.java.tcs.pbg - This package contains the parameter
       block generator. This is the TSS component that creates the command
       byte streams that are sent to the TPM.

     * iaik.tc.tss.impl.java.tcs.sessmgr - This package provides session
       management as defined in the 1.2 TPM specification.

     * iaik.tc.tss.impl.java.tcs.tcsi - This package contains the TCS
       interface (TCSI) being the TCS API used by callers (such as the TSP).

     * iaik.tc.tss.impl.java.tcs.tddl - This package contains the TDDL for
       different operating systems. The TDDL is the layer that directly
       interacts with the TPM driver (e.g. via a device file or some other OS
       specific mechanism).

   Common parts shared by TSP and TCS

   There are several components that are required by both, the TSP and the
   TCS. Consequently, these components are located in a common source folder.
   The common components include e.g. constants for the TPM and TCS, TSS and
   TPM level structures, the persistent storage implementation, common crypto
   building blocks and utilities.

   Two persistent storage (PS) implementations are provided as demonstrators.

   One uses the OS file system (FS) as data repository. In the .ini files,
   two different directories for both storages (system and user) must be
   specified. There must be a single system storage for the TCS and a user
   storage for each user (for instance /home/<username>/.tpm/user_storage).
   Care must be taken with FS access rights to protect the storage. While the
   directory structure will automatically be created upon usage, it is a good
   idea to create the directories and set the permissions before starting
   jTSS.

   The second implementation uses a relational database.

   Depending on usage requirements a specific implementation might be
   necessary. Therefore, custom Java classes for persistent storage can be
   implemented and configured in the .ini files. Any implementation must
   implement the iaik.tc.tss.impl.ps.TcITssPersistentStorage interface.

   When ownership of the TPM is taken, the storage root key (SRK) will be
   stored in the system storage (without the private key part). Note, that in
   general the TSS specifications require the application programmer to take
   care that a valid key hierarchy is created and maintained in the storage.

7. SOAP Bindings

  7.1. Introduction

   The Trusted Computing Group specifies the communication between the
   Trusted Core Service (TCS) and the Trusted Service Provider (TSP) in the
   [13]TSS Specification. One of these ways of communication is the Simple
   Object Access Protocol (SOAP). It is an XML based protocol that provides
   additional functionality if compared to simple RPC calls. The interface of
   the communication is specified in an XML document called Web Service
   Definition Language (WSDL) file which defines the procedure calls and
   their according parameters.

   The TCS is a daemon that runs as a simple webserver and this package
   contains all necessary libraries for the entire SOAP communication.
   To specify parameters for the TCS and the TSP one can find further
   information in the lib/ini/*.ini files under section [SOAP]. While the
   TCG-specified TCP port for TSS would be 30003, we ship jTSS configured to
   use port 30004. This avoids collisions with other TSS implementations
   (mainly on Windows).

   TSP and TCS need additional 3rd party libraries that provide support for
   the SOAP communication. One can find a list with the versions and the
   according license model of these libraries in Section "Versions and
   Licences of the Required Libraries".

  7.2. The Trusted Core Service under Linux

   the Java TCS as Linux system daemon. In Ubuntu, these libraries are called
   jsvc and libcommons-daemon-java and you can install them with the package
   manager.

   We provide a script called tcs_daemon.sh in the soap directory of jTSS to
   start, restart, and stop the TCS daemon. Ensure to have a proper working
   TPM and execute these scripts as root:

   Start the TCS as daemon

           Start the TCS, detach it from the terminal and display the debug
           output in the terminal. "Detaching" means that the TCS keeps
           running if the terminal terminates. Additionally, the debug output
           (Std and Err) can be found in the file log/out.log. Change to
           directory soap and

           user@localhost:jTSS$ sudo bash tcs_daemon.sh

   Stop the TCS daemon

           Stop the TCS daemon if it is running.

           user@localhost:jTSS$ sudo bash tcs_daemon.sh stop

   Start the TCS but do not detach it from the terminal

           Display debugging information of the TCS and the entire SOAP
           communication in the terminal. You can terminate the TCS by
           pressing <Ctrl> + C.

           user@localhost:jTSS$ sudo bash tcs_daemon.sh f

   Restart the TCS

           Stop the TCS if it is running and immediately start it again.
           Just start the TCS if it is not running.

           user@localhost:jTSS$ sudo bash tcs_daemon.sh restart

   Print this document

           user@localhost:jTSS$ bash tcs_daemon.sh help

  7.3. The Trusted Core Service under Windows Vista

   The TCS is installed as a Windows Service. Start a windows command prompt
   with elevated administrative privileges and navigate to the jTss
   directory. NOTE: If you log off or restart your machine the TCS will still
   run. Further, ensure to surround a user defined path with quotation marks
   if it contains any spaces e.g. "c:\this is a\path to my\script.bat". The
   delivered "soap\ext_libs\x86\prunsrv.exe",
   "soap\ext_libs\amd64\prunsrv.exe", and "soap/ext_libs/tcsdaemonw.exe" are
   taken from the the Apache Tomcat servlet container and provide start,
   stop, and restart functionality. The licenses for both can be found at the
   Apache

   Start the TCS as Windows Service

           This script installs and starts the TCS as a Windows Service. All
           debugging information is written to log\out.txt and log\err.txt.+
           c:\>jTSS> soap\install.bat start

   Stop the TCS Windows Service

           This script stops the running TCS Windows Service. Keep in mind
           that it just stops the Service and does not remove it from
           Windows' Service list.

           c:\>jTSS> soap\install.bat stop

   Remove the TCS Windows Service

           If necessary, stop the TCS Service and remove it from Windows'
           Service list.

           c:\>jTSS> soap\install.bat remove

   Restart the TCS Windows Service

           Stop and remove the Service if it is running and immediately start
           it again. If it is not running just start it.

           c:\>jTSS> soap\install.bat restart

   Print this document

           c:\>jTSS> soap\install.bat help

   Note: The Setup.exe installer and uninstaller will automatically perform
   these tasks.

  7.4. SOAP Package Structure

   In the following we shortly describe the package structure of the SOAP
   implementation.

     * iaik.tc.tss.impl.java.tcs.soapservice.ConvertDataTypesServer.java -
       Translate the datatypes used in the SOAP protocol to the datatypes
       used by the TCS and vice versa.

     * iaik.tc.tss.impl.java.tcs.soapservice.TSSCoreServiceBindingImpl.java -
       Implement the wrapping of the TCS parameters to transport them via
       SOAP.

     * iaik.tc.tss.impl.java.tcs.soapservice.server.StartAxisServer.java -
       Start the AXIS Server that provides a SOAP interface for all TCS
       functions.

     * iaik.tc.tss.impl.java.tcs.soapservice.serverties - Contains the
       autogenerated Java files derived from the WSDL file.

     * iaik.tc.tss.impl.java.tsp.tcsbinding.soapservice.ConvertDataTypesClient.java
       - This class implements the same methods as the corresponding file
       ConvertDataTypesServer.java on the server side.

     * iaik.tc.tss.impl.java.tsp.tcsbinding.soapservice.ConvertRemoteExceptions.java
       - Unwrap the SOAP exceptions to get the nested TSS Exceptions.

     * iaik.tc.tss.impl.java.tsp.tcsbinding.soapservice.TcTcsBindingSoap.java
       - Unwrap the parameters received from the SOAP network to use it in
       the TSP.

     * iaik.tc.tss.impl.java.tsp.tcsbinding.soapservice.clientstubs -
       Contains the autogenerated Java files derived from the WSDL file.

  7.5. Generate the WSDL File

   As there are some missing functions in the WSDL files provided by ([14]TSS
   Specification) we have to modify it. To do so, extract the tcs.wsdl from
   ([15]TSS Specification) and copy it to the soap directory. Then apply the
   patch:

   user@localhost:jTSS/soap$ patch -p0 tcs.wsdl tcs.wsdl.patch

   The patch process detects a previous patch of this file. Therefore press y
   to apply the patch anyhow.

   Changes in the patched tcs.wsdl are now clearly marked with

 <!-- Begin: Additional implementation as it is
             not specified in the origin WSDL file       -->

 Here is the new code

 <!-- End:   Additional implementation as it is
             not specified in the origin WSDL file       -->

  7.6. Generate SOAP Jars

   Use the build.xml file in the src directory to get the jar files for the
   jTss with SOAP support.

   user@localhost:jTSS/src$ ant jars_soap

   First, this task builds the complete jTSS Stack without any SOAP support.
   Then it creates the Java framework from the WSDL files and compiles these
   files. Finally, it generates two additional jar files: one for the SOAP
   support in the TCS and the other for the SOAP support in the TSP.

8. Versions and Licences of the Required Libraries

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

                    [16]Sun JavaBeans

            License

                    [17]Sun JavaBeans License

            Contains

                    activation.jar

    2. Axis Version 1.4 final

            Download

                    [18]Apache Axis

            License

                    [19]Apache Axis License Version 2

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

                    [20]Apache Daemon

            License

                    [21]Apache Daemon License Version 2

            Contains

                    commons-daemon.jar

    4. JavaMail API Version 1.4.1

            Download

                    [22]Sun JavaMail

            License

                    [23]COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL)

            Contains

                    mail.jar

    5. Microsoft Visual C++ Runtime Redistributable 2008 (x86 and x64)
       (Windows only)

            Download

                    [24]http://www.microsoft.com/downloads

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

                    [25]HSQL - 100% Java Database

            License

                    [26]ORIGINAL LICENSE (a.k.a. "hypersonic_lic.txt")

            Contains

                    hsqldbmin.jar

   The setup.exe Installer is created with Innosetup (Windows only).

    1. Inno Setup License

            Download

                    [27]Inno Setup

            License

                    [28]Inno Setup License

            Contains

                    setup.exe (installer code only)

9. Further Help

   This software is provided "as is". However, a mailing list
   trustedjava-support@lists.sourceforge.net is maintained at [29]Trusted
   Computing for the Java (tm) Platform to assist users and to allow users to
   help each other. You are invited to join the discussion, but kindly take a
   look at the mailing list archive before posting a question.

10. Copyright Notice

   The copyright for contents of the IAIK jTSS package, including all related
   documentation, is owned by [30]IAIK, Graz University of Technology.

   The API documentation (JavaDoc) is partially based on the descriptions and
   documentation contained in the TPM and TSS specifications of the TCG.
   Where possible, line numbers pointing to these specifications are included
   in the API documentation.

11. Trademarks

   Java (tm) and all Java (tm) based marks are a trademark or registered
   trademark of Sun Microsystems, Inc, in the United States and other
   countries. All other trademarks and copyrights are property of their
   respective owners.

12. Revision History

   +------------------------------------------------------------------------+
   | date       | version | comment                                         |
   |------------+---------+-------------------------------------------------|
   | 2014/07/17 | 0.7.1a  | Bugfix wrt. jsvc                                |
   |------------+---------+-------------------------------------------------|
   | 2013/12/17 | 0.7.1   | Bugfixes, experimental RPi support              |
   |------------+---------+-------------------------------------------------|
   | 2012/05/25 | 0.7a    | Enabled OS detection for Windows 8, Windows     |
   |            |         | Server 2008R2,                                  |
   |------------+---------+-------------------------------------------------|
   |            |         | and future versions. Updated VC++2008 runtime.  |
   |------------+---------+-------------------------------------------------|
   | 2011/09/15 | 0.7     | Tutorial, bugfixes, improved default            |
   |            |         | configuration,                                  |
   |------------+---------+-------------------------------------------------|
   |            |         | ini-file setup now optional, support for JSR321 |
   |------------+---------+-------------------------------------------------|
   |            |         | implementations, better monotonic counter       |
   |            |         | support,                                        |
   |------------+---------+-------------------------------------------------|
   |            |         | improved simple test tool.                      |
   |------------+---------+-------------------------------------------------|
   |            |         | Bugfixes, improvements to debian package,       |
   | 2010/10/04 | 0.6     | reporting of more capabilities, external key    |
   |            |         | import, extended test tool, improved actvsm     |
   |            |         | support                                         |
   |------------+---------+-------------------------------------------------|
   | 2010/07/26 | 0.5.2   | (internal release only) Bugfixes and support    |
   |            |         | for acTvSM platform                             |
   |------------+---------+-------------------------------------------------|
   | 2010/06/01 | 0.5.1   | (internal release only) Bugfixes and support    |
   |            |         | for IBM Software TPM sockets                    |
   |------------+---------+-------------------------------------------------|
   |            |         | Bugfixes and new deployment structure. Debian   |
   | 2010/03/04 | 0.5     | packages. socket is now 30004, updates to       |
   |            |         | readme and license texts.                       |
   |------------+---------+-------------------------------------------------|
   | 2009/12/02 | 0.4.2   | Bugfixes and improvements build and install     |
   |            |         | system (internal release only)                  |
   |------------+---------+-------------------------------------------------|
   | 2009/11/19 | 0.4.1a  | Minor bugfixes; sets up on AMD64 Windows        |
   |            |         | (experimental) (internal release only)          |
   |------------+---------+-------------------------------------------------|
   |            |         | many bugfixes, adv. EK functions, full NV-RAM   |
   | 2009/08/24 | 0.4.1   | impl. for Tboot, exp. Windows 7 and Server 2008 |
   |            |         | support.                                        |
   |------------+---------+-------------------------------------------------|
   |            |         | (internal release only) Bugfixes, minimal       |
   | 2009/05/19 | 0.4b    | NV-RAM access implementation for IFX EK         |
   |            |         | certificate extraction.                         |
   |------------+---------+-------------------------------------------------|
   | 2009/02/27 | 0.4a    | Bugfixes                                        |
   |------------+---------+-------------------------------------------------|
   |            |         | NV access headers, migration, CMK, flat file    |
   |            |         | event log, SQL-Databased PS, monotonic          |
   | 2008/12/12 | 0.4     | counters, complete SOAP bindings, Windows       |
   |            |         | installer, tests, TrouSerS PS import tool, bug  |
   |            |         | fixes                                           |
   |------------+---------+-------------------------------------------------|
   | 2008/04/17 | 0.3     | SOAP interface, NV read access (TCS),           |
   |            |         | additional test cases, bugfixes                 |
   |------------+---------+-------------------------------------------------|
   | 2007/08/31 | 0.2     | persistent storage, time stamping, bugfixes     |
   |------------+---------+-------------------------------------------------|
   | 2007/04/24 | 0.1     | initial release                                 |
   +------------------------------------------------------------------------+

   --------------------------------------------------------------------------

   Last updated 2014-07-17 15:24:33 CEST

References

   Visible links
   1. http://www.trustedcomputinggroup.org/
   2. http://www.iaik.tugraz.at/content/research/trusted_computing/actvsm/
   3. http://www.iaik.tugraz.at/
   4. http://www.tugraz.at/
   5. http://www.gnu.org/licenses/gpl.html
   6. http://jce.iaik.tugraz.at/sic/sales/licences/commercial
   7. http://msdn.microsoft.com/en-us/library/aa446796%28v=VS.85%29.aspx
   8. http://java.sun.com/javase/downloads/index.jsp
   9. https://developer.berlios.de/projects/tpm-emulator/
  10. http://msdn.microsoft.com/en-us/library/aa446796%28v=VS.85%29.aspx
  11. http://technet.microsoft.com/en-us/library/cc749022(WS.10).aspx
  12. http://www.trustedcomputinggroup.org/resources/tcg_software_stack_tss_specification
  13. https://www.trustedcomputinggroup.org/specs/TSS/tss12_Header_File_final.zip
  14. https://www.trustedcomputinggroup.org/specs/TSS/tss12_Header_File_final.zip
  15. https://www.trustedcomputinggroup.org/specs/TSS/tss12_Header_File_final.zip
  16. http://java.sun.com/products/javabeans/jaf/downloads/index.html
  17. http://developers.sun.com/license/berkeley_license.html
  18. http://ws.apache.org/axis/
  19. http://commons.apache.org/license.html
  20. http://commons.apache.org/downloads/download_daemon.cgi
  21. http://commons.apache.org/license.html
  22. http://java.sun.com/products/javamail/
  23. http://www.opensource.org/licenses/cddl1.php
  24. http://www.microsoft.com/downloads/details.aspx?familyid=200b2fd9-ae1a-4a14-984d-389c36f85647&displaylang=en
  25. http://hsqldb.org/
  26. http://hsqldb.org/web/hsqlLicense.html
  27. http://www.innosetup.com/isinfo.php
  28. http://www.innosetup.com/files/is/license.txt
  29. http://trustedjava.sf.net/
  30. http://www.iaik.tugraz.at/
