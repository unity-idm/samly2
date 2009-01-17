#
#Installation Directory
#
dir=`dirname $0`
if [ "$dir" != "." ]
then
  INST=`dirname $dir`
else
  pwd | grep -e 'bin$' > /dev/null
  if [ $? = 0 ]
  then
    # we are in the bin directory
    INST=".."
  else
    # we are NOT in the bin directory
    INST=`dirname $dir`
  fi
fi

INST=${INST:-.}

#
#Alternatively specify the installation dir here
#
#INST=


#
#Java command 
#
JAVA=java


#
#Memory for the VM
#
MEM=-Xmx128m

#
#Options
#
#log config file
# OPTS=$OPTS" -Djava.util.logging.config.file=conf/logging.properties"

cd $INST

#
#put all jars in lib/ on the classpath
#
JARS=lib/*.jar
CP=.
for JAR in $JARS ; do 
    CP=$CP:$JAR
done
CP=${CP}:conf

#echo Reading code from $CP