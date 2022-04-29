# HQC Attack

## Perform the attack once:

```
make attack
```

## Collect timing information:

```
make collect-timings # takes ~1 hour on a Ryzen 9 5900X (single-threaded)
```

To get the best results:
- set process niceness to -20 (using `nice -n-20 CMD`)
- pin the process to a single core, and all other processes to a different one (using `taskset -p 0x1`, etc)
- disable simultaneous multi-threading
- disable dynamic frequency scaling
- do not use the system for anything else 

## Run the attack 1000 times and gather statistics:

```
make attackstats # takes ~0.75 hours on a Ryzen 9 5900X (multi-threaded)
```

## Create figures:

```
make figures # Must make collect-timings and attackstats before making figures!
```
