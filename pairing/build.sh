#script used to compile developed code
C_PROJECT=$(pwd)
RELIC=$(pwd)/relic
JAVA_PATH=$2
C_SRC=$1

mkdir -p $C_PROJECT/lib

gcc $C_PROJECT/src/$C_SRC -shared -o $C_PROJECT/lib/libPairing.so -fPIC -g -L$RELIC/relic-target/lib -I$RELIC/relic-target/include -I$RELIC/include -I$JAVA_PATH/include -I$JAVA_PATH/include/linux -I$C_PROJECT/headers -lrelic