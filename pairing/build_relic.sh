RELIC_DIR=$(pwd)/relic

unzip $RELIC_DIR/relic.zip -d $RELIC_DIR/ && mkdir -p $RELIC_DIR/relic-target && cd $RELIC_DIR/relic-target && cmake -DFP_PRIME=381 ../ && make