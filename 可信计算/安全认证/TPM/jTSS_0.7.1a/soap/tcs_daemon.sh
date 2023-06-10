#!/bin/bash
#
# Copyright (C) 2008 IAIK, Graz University of Technology
#
# This script starts the jTSS Core Services as a Linux daemon.
# Further it provides functions to restart, stop, and remove this daemon.


#SHAREDIR=
#LOGDIR=
#RUNDIR=

if [[ -n "${SHAREDIR}" ]] ; then
    ROOT="${SHAREDIR}"
else
    FULLPATH="$(readlink -f "${0}")"
    DIR="$(dirname "${FULLPATH}")"  # the absolute directory this script is located in
    ROOT="$(readlink -f "${DIR}"/..)"
fi


# log and pidfiles

# use system locations if run as root
if [[ "${EUID}" == 0 ]] ; then
    [[ -z "${LOGDIR}" ]] && LOGDIR=/var/log/jTSS
    [[ -z "${RUNDIR}" ]] && RUNDIR=/var/run
else
    [[ -z "${LOGDIR}" ]] && LOGDIR="${ROOT}"/log
    [[ -z "${RUNDIR}" ]] && RUNDIR="${ROOT}"/run
fi

LOGFILE="${LOGDIR}"/tcs_daemon.log
PIDFILE="${RUNDIR}"/tcs_daemon.pid


# application setup

EXTLIBS="${ROOT}"/ext_libs
LIBS="${ROOT}"/lib

CLASSPATH_SOAP=()
CLASSPATH_SOAP+="${EXTLIBS}"/activation.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/axis-ant.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/axis.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/commons-daemon.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/commons-discovery-0.2.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/commons-logging-1.0.4.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/jaxrpc.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/log4j-1.2.8.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/mail.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/saaj.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/wsdl4j-1.5.1.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/xerces.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/hsqldbmin.jar

CLASSPATH_SOAP+=:"${LIBS}"/iaik_jtss_tcs.jar
CLASSPATH_SOAP+=:"${LIBS}"/iaik_jtss_tcs_soap.jar
CLASSPATH_SOAP+=:"${LIBS}"/iaik_jtss_tsp.jar
CLASSPATH_SOAP+=:"${LIBS}"/iaik_jtss_tsp_soap.jar
CLASSPATH_SOAP+=:"${LIBS}"/iaik_jtss_tsp_tests.jar
CLASSPATH_SOAP+=:"${EXTLIBS}"/junit.jar
CLASSPATH_SOAP+=:"${ROOT}"/soap

# Set the name of the java class that contains the main()
EXECUTABLE=iaik.tc.tss.impl.java.tcs.soapservice.server.StartAxisServerLinux


# Stop the TCS if it's running.

stop ()
{
  if [[ -f "${PIDFILE}" ]]
  then
    echo "Try to stop the TCS..."
    jsvc -pidfile "${PIDFILE}" -stop -cp ${CLASSPATH_SOAP} ${EXECUTABLE}
    echo "TCS successfully stopped"
  else
    echo "There is no TCS running"
    return 1
  fi
}


# Start the TCS if it's not running.

start ()
{
  if [[ ! -f "${PIDFILE}" ]]
  then
    echo -n "Try to start the TCS "

    # Direct both, the std and err output to the logfile
    # To access the wsdd file we have to change to the script's directory
    # and after the jsvc command go back again.

    TIMEOUT=10  # Timeout in seconds

    pushd "${ROOT}"/soap &> /dev/null
    jsvc -pidfile "${PIDFILE}" \
         -outfile "${LOGFILE}" \
         -errfile '&1' \
         -wait ${TIMEOUT} \
         -cp ${CLASSPATH_SOAP} ${EXECUTABLE}
    popd &> /dev/null


    # If there is no PID file the jsvc did not start up. Exit.

    if [[ ! -f "${PIDFILE}" ]]
    then
      echo
      echo "Could not start the TCS."
      exit 0
    fi

    echo
    echo "TCS successfully started"
    echo
  else
    echo "The TCS is already running"
    return 1
  fi
}


# Start the TCS and run it in foreground

foreground ()
{
  if [[ ! -f "${PIDFILE}" ]]
  then
    echo "Start the TCS and run it in foreground"
    echo "Stop by pressing <Ctrl> + C"
    java -cp ${CLASSPATH_SOAP} ${EXECUTABLE}
  else
    echo "The TCS is already running"
    return 1
  fi
}


check() {
    # The script requires a JAVA_HOME variable

    if [[ -z "${JAVA_HOME}" ]]
    then
        echo "ERROR: You have to specify the JAVA_HOME variable"
        return 1
    fi


    # Check which jars exist and decide how to proceed

    if [[ ! -f "${LIBS}"/iaik_jtss_tcs_soap.jar ]] || [[ ! -f "${LIBS}"/iaik_jtss_tsp_soap.jar ]]
    then
        if [[ -f "${LIBS}"/iaik_jtss_tcs.jar ]] || [[ -f "${LIBS}"/iaik_jtss_tsp.jar ]]
        then
            echo "Re-run the ant script with the \"jars_soap\" parameter."
        else
            echo "Could not find the jTSS libraries."
            echo "See README.txt for further information."
        fi
        return 1
    fi
}



# Create log and run directories if necessary

[[ ! -d "${LOGDIR}" ]] && mkdir -p "${LOGDIR}"
[[ ! -d "${RUNDIR}" ]] && mkdir -p "${RUNDIR}"


# Process the given arguments and run the according function.

case "${1}" in
  "help")
    less "${ROOT}"/jtss_readme.txt
    ;;
  "f")
    check && foreground
    ;;
  "start" | "stop")
    check && ${1}
    ;;
  "restart")
    stop && check && start
    ;;
  *)
    echo "Invalid parameter. Use help for more information."
    exit 1
esac

exit ${?}

