#script used to compile relic library
RELIC_DIR=$(pwd)/relic
RELIC_ZIP=$1

unzip $RELIC_DIR/$RELIC_ZIP -d $RELIC_DIR/ && mkdir -p $RELIC_DIR/relic-target && cd $RELIC_DIR/relic-target && cmake -DFP_PRIME=256 ../ && make