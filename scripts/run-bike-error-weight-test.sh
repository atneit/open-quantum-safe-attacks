#!/bin/bash

echo "This script must be running from repository root"

LEN=1000000
THREADS=10
RELEASE="--release"
ALG="kem-l1"
ROOT="data/compressed/bike-l1"
SUFFIX="csv.gz"
LOGSUFFIX="log"
DB="rejection-sampling-plaintexts.db"
BASE=$ROOT/$ALG-$LEN

for HW in {160..148}; do
    DEST=$BASE-hw$HW-orig
    LOGDEST=$DEST.$LOGSUFFIX
    if [[ -f "$DEST" ]]; then
        echo "$DEST already exists"
    else
        cargo run $RELEASE -- --logdest $LOGDEST attack rejection-sampling bike-error-weight-test --db $DB --tests $LEN --weight $HW --threads=$THREADS $ALG
    fi
done
