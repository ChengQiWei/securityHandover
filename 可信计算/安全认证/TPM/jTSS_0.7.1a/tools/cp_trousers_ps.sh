#!/bin/sh
# 
#  Copyright (C) 2008 IAIK, Graz University of Technology
#  
#  Copies the TrouSerS persistent storage to the jTSS persistent storage

FULLPATH=`readlink -f $0`
DIR=`dirname $FULLPATH`  # the absolute directory this script is located in

LIBPATH=$DIR/../ext_libs/

CLASSPATH_LOCAL=${LIBPATH}/hsqldbmin.jar

CLASSPATH_LOCAL=$DIR/../lib/iaik_jtss_tcs.jar:$CLASSPATH_LOCAL
CLASSPATH_LOCAL=$DIR/../lib/iaik_jtss_tcs_soap.jar:$CLASSPATH_LOCAL
CLASSPATH_LOCAL=$DIR/../lib/iaik_jtss_tsp.jar:$CLASSPATH_LOCAL
CLASSPATH_LOCAL=$DIR/../lib/iaik_jtss_tsp_soap.jar:$CLASSPATH_LOCAL
CLASSPATH_LOCAL=$DIR/iaik_jtss_tsp_tests.jar:$CLASSPATH_LOCAL
CLASSPATH_LOCAL=$DIR/iaik_jtss_tools.jar:$CLASSPATH_LOCAL

java -cp $CLASSPATH_LOCAL iaik.tc.tss.tools.ps.TcTssGetTrousersPs "$@"