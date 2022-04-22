#!/bin/env python3

import sys

if sys.gettrace():
    #We are running in a debugger
    old = sys.argv
    sys.argv = [old[0], "/tmp/cache-profile.csv", "/tmp/cache-profile.pgf", "title", "7500000", "0-MOD", "0-NOMOD"]

if len(sys.argv) < 4:
    print("Usage: data.csv output.pgf title maximum-value COLUMN1 [COLUMN2 [COLUMN3 [...]]]")
    sys.exit(1)
    
csvname = sys.argv[1]
pgfoutputname = sys.argv[2]
title = sys.argv[3]
#samplesize = int(sys.argv[2])
percentage = 1.0#0.75  #float(sys.argv[3]) / 100
minmax = sys.argv[4].split("-")
try:
    maxval = int(minmax[1])
    minval = int(minmax[0])
except:
    maxval = int(minmax[0])
    minval = 0
colspec = sys.argv[5:]
writetofile = pgfoutputname != "-"

import matplotlib

if writetofile:
    matplotlib.use("pgf")
matplotlib.rcParams.update({
    "pgf.texsystem": "pdflatex",
    'font.family': 'serif',
    'text.usetex': True,
    'pgf.rcfonts': False
})

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from pandas.core.algorithms import value_counts
import re

sns.set()
sns.set_context("paper")

origdata = pd.read_csv(csvname, sep=',', header=0)

data = pd.DataFrame(columns=["clock cycles", "keynum", "ciphertext", "modified"])

for column in origdata:
    add = False
    for spec in colspec:
        if spec in column:
            add = True
    if add:
        parts = column.split("-")
        try:
            keynum = parts[0]
            ciphertext = parts[1]
            modified = parts[2] != "MINOR" and parts[2] != "NOMOD"
        except:
            keynum = 1
            ciphertext = parts[0]
            modified = parts[1] != "MINOR" and parts[1] != "NOMOD"

        clock_cycles = pd.DataFrame(origdata[column][(origdata[column] < maxval) & (origdata[column] > minval)])
        clock_cycles.rename(columns={column: "clock cycles"}, inplace=True)
        mlen = len(clock_cycles)
        plen = len(data)
        print("adding {}(len {}) to data(len {}) with ciphertex '{}' and modified '{}'".format(column, mlen, plen, ciphertext, modified))
        
        data = data.append(clock_cycles, ignore_index=True)
        data.loc[plen: plen + mlen, ["keynum", "ciphertext", "modified"]] = [keynum, ciphertext, modified]
        
data = data.apply(pd.to_numeric) # convert all columns of DataFrame to numerics/floats

print(data)


axis = sns.catplot(data=data, kind="violin", x="clock cycles", y="ciphertext", hue="modified", col="keynum", orient="h", col_wrap=2, split=True, scale="count", inner="quartile", scale_hue=False, cut=0)

#close button in upper right corner
btnax = plt.axes([0.98, 0.975, 0.01, 0.015])
btn = matplotlib.widgets.Button(btnax, "X")
btn.on_clicked(lambda event: plt.close())

manager = plt.get_current_fig_manager()
manager.full_screen_toggle()
plt.show()