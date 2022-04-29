#!/usr/bin/env bash

for variant in original countermeasure_{1,2,3}
do 
    cp src/vector_$variant.c src/vector.c
    make collect-timings collect-timings-messages
    cp src/vector_original.c src/vector.c
    echo collecting timings for $variant
    ./bin/collect-timings results/timings/timings_$variant.csv
    echo collecting messages timings for $variant
    ./bin/collect-timings-messages results/timings/timings_messages_$variant.csv
done