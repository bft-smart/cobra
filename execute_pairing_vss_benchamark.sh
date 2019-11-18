JAVA_PROJECT=$(pwd)/lib
C_PROJECT=$(pwd)/pairing
RELIC=$(pwd)/pairing/relic/relic-target

export LD_LIBRARY_PATH=$RELIC/lib:$LD_LIBRARY_PATH

java -cp $JAVA_PROJECT/VerifiableSecretSharing.jar -Djava.library.path=$C_PROJECT/lib vss.benchmark.PairingVSSOverallBenchmark $@