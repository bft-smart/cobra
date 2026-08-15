#!/usr/bin/env bash
set -euo pipefail

RELIC_ROOT=$(pwd)/relic
RELIC_SRC=$RELIC_ROOT
RELIC_BUILD=$RELIC_ROOT/relic-target

PRESET_NAME="x64-pbc-bls12-381.sh"
CUSTOM_PRESET=$RELIC_BUILD/$PRESET_NAME

# Extract RELIC
unzip relic.zip -d $RELIC_ROOT

# Always use a clean build directory when changing configurations.
rm -rf $RELIC_BUILD
mkdir -p $RELIC_BUILD
cd $RELIC_BUILD

sed \
  -e 's/-DSHLIB=OFF/-DSHLIB=ON/' \
  -e 's/-DSTBIN=ON/-DSTBIN=OFF/' \
  -e 's/-DCHECK=off/-DCHECK=on/' \
  $RELIC_ROOT/preset/$PRESET_NAME \
  > $CUSTOM_PRESET

# Configure RELIC using the BLS12-381 preset.
sh $CUSTOM_PRESET $RELIC_ROOT

# Compile.
cmake --build .

make