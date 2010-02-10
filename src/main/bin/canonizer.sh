#!/bin/sh


#
# starts UVOS WS server
#

source "`dirname $0`"/_setenv.sh

#OPTS=$OPTS" -Xdebug -Xrunjdwp:transport=dt_socket,address=6009,server=y,suspend=n"

$JAVA ${MEM} ${OPTS} ${DEFS} -cp ${CP} eu.unicore.security.dsig.StandaloneCanonizer $1 $2 $3
