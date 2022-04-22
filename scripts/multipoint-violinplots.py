#!/bin/env python3

import re
from pandas.core.algorithms import value_counts
import seaborn as sns
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
import sys
import itertools as IT
import gc

if sys.gettrace():
    # We are running in a debugger
    old = sys.argv
    sys.argv = [old[0], "/tmp/cache-profile.csv",
                "/tmp/cache-profile.pgf", "title", "7500000", "0-MOD", "0-NOMOD"]

if len(sys.argv) < 2:
    print(
        "Usage: data.csv output.pgf title maximum-value COLUMN1 [COLUMN2 [COLUMN3 [...]]]")
    sys.exit(1)

csvname = sys.argv[1]
pgfoutputname = sys.argv[2]
targetlist = sys.argv[3:]

# if writetofile:
#     matplotlib.use("pgf")
# matplotlib.rcParams.update({
#     "pgf.texsystem": "pdflatex",
#     'font.family': 'serif',
#     'text.usetex': True,
#     'pgf.rcfonts': False
# })


sns.set()
sns.set_context("paper")


def valid(chunks):
    for chunk in chunks:
        if not targetlist:
            print("+", end="", flush=True)
            yield chunk
        else:
            mask = False
            for target in targetlist:
                mask = mask | (chunk["target"] == target)
            if mask.all():
                print("+", end="", flush=True)
                yield chunk
            elif mask.any():
                print("/", end="", flush=True)
                yield chunk.loc[mask]
            else:
                print("-", end="", flush=True)
    print("")


chunksize = 10 ** 5
chunks = pd.read_csv(csvname, chunksize=chunksize, header=0)
data = pd.concat(valid(chunks))

print(data)

print("Creating plot...")
facetgrid = sns.catplot(data=data, kind="violin", x="clock cycles", y="ciphertext", hue="modified", col="target",
                   row="keynum", orient="h", split=True, scale="count", inner="quartile", scale_hue=False, cut=0,
                   sharex="col")

print("Displaying plot...")

# close button in upper right corner
btnax = plt.axes([0.98, 0.975, 0.01, 0.015])
btn = matplotlib.widgets.Button(btnax, "X")
btn.on_clicked(lambda event: plt.close())

manager = plt.get_current_fig_manager()
manager.full_screen_toggle()
plt.subplots_adjust(top=0.9)
facetgrid.fig.suptitle(csvname)
plt.show()
