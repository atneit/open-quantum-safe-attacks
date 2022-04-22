#!/bin/bash

LEN=100000
HW=${1:-150}
EPSILON=0.01
THREADS=12
RELEASE="--release"
ALG="kem-l1"
ROOT="data/compressed/bike-l1"
KEYPAIR="$ROOT/$ALG.keypair"
SUFFIX="csv.gz"
LOGSUFFIX="log"
DB="rejection-sampling-plaintexts.db"
BASE=$ROOT/$ALG-hw$HW-$LEN-ep$EPSILON

for IDX in {00..19}; do
    DEST=$BASE-$IDX.$SUFFIX
    LOGDEST=$BASE-$IDX.$LOGSUFFIX
    if [[ -f "$DEST" ]]; then
        echo "$DEST already exists"
    else
        cargo run $RELEASE -- --logdest $LOGDEST attack rejection-sampling bike-attack --chain-length $LEN --db $DB --hamming-weight $HW --epsilon $EPSILON --destination $DEST --threads=$THREADS --reuse-key-pair $KEYPAIR $ALG
    fi
done
