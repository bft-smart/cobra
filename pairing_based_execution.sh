JAVA_PROJECT=$(pwd)/lib
JAVA_PROJECT_2=$(pwd)/bin
C_PROJECT=$(pwd)/pairing
RELIC=$(pwd)/pairing/relic/relic-target

export LD_LIBRARY_PATH=$RELIC/lib:$LD_LIBRARY_PATH

java -cp $JAVA_PROJECT/*:$JAVA_PROJECT_2/* -Djava.library.path=$C_PROJECT/lib $@