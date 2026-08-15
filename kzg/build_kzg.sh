C_PROJECT=$(pwd)
RELIC=$(pwd)/relic

mkdir -p $C_PROJECT/lib

gcc -Wall -Wextra -fPIC -shared -o lib/libdl_kzg_commitments.so src/dl_kzg_commitments.c -Irelic/include -Irelic/relic-target/include -Iheaders -Lrelic/relic-target/lib -lrelic
gcc -Wall -Wextra -fPIC -shared -o lib/libped_kzg_commitments.so src/ped_kzg_commitments.c -Irelic/include -Irelic/relic-target/include -Iheaders -Lrelic/relic-target/lib -lrelic