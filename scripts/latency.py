#!/bin/env python3

import sys

if sys.gettrace():
    # We are running in a debugger
    old = sys.argv
    sys.argv = [
        old[0],
        "/tmp/cache-profile.csv",
        "/tmp/cache-profile.pgf",
        "title",
        "7500000",
        "MOD",
        "NOMOD",
    ]

if len(sys.argv) < 4:
    print(
        "Usage: data.csv output.pgf title maximum-value COLUMN1 [COLUMN2 [COLUMN3 [...]]]"
    )
    sys.exit(1)

csvname = sys.argv[1]
pgfoutputname = sys.argv[2]
title = sys.argv[3]
# samplesize = int(sys.argv[2])
percentage = 1.0  # 0.75  #float(sys.argv[3]) / 100
maxval = int(sys.argv[4])
colspec = sys.argv[5:]
writetofile = pgfoutputname != "-"

import matplotlib

if writetofile:
    matplotlib.use("pgf")
matplotlib.rcParams.update(
    {
        "pgf.texsystem": "pdflatex",
        "font.family": "serif",
        "text.usetex": True,
        "pgf.rcfonts": False,
    }
)

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from pandas.core.algorithms import value_counts
import re

sns.set()
sns.set_context("paper")

data = pd.read_csv(csvname, sep=",")

columns = []
for spec in colspec:
    if spec.startswith("#"):
        index = int(spec[1:])
        if index not in columns:
            columns.append(data.columns[index])
    else:
        for col in data.columns:
            if col not in columns and re.search(spec, col):
                columns.append(col)

print("Selected columns: " + repr(columns))

if not columns:
    sys.exit(0)


def usecol(col):
    d = data[col]
    last = int(len(d) * percentage)
    return d[0:last][d < maxval]  # .sample(samplesize)


def getlabel(colname):
    if "NOMOD" in colname:
        return "[{}] $x=0$".format(colname.split("-")[0])
    elif "MINOR" in colname:
        return "[{}] $x=1$".format(colname.split("-")[0])
    elif "MAJOR" in colname:
        return "[{}] $x=2^{{D-B}}$".format(colname.split("-")[0])
    elif "MOD" in colname:
        return "[{}] $x=2^{{D-B}}$".format(colname.split("-")[0])
    else:
        return colname.replace("{", "\{").replace("}", "\}")


colors = sns.color_palette("cubehelix", len(columns))
axis = None
height = 0.25
heightstep = height / (len(columns) + 1)
prevmean = None
prevmin = None
for (i, col) in enumerate(columns):
    height -= heightstep
    d = usecol(col)
    # axis = sns.distplot(d, label=getlabel(col), kde=True, bins=80, ax=axis, kde_kws={'cut':0, 'bw': 0.1}, color=colors[i])
    axis = sns.kdeplot(d, label=getlabel(col), cut=0, ax=axis, color=colors[i])
    mean = d.mean()
    minimum = d.min()
    origlen = len(data[col]) - data[col].isnull().sum()
    percentage = len(d) / origlen * 100
    index = data.columns.get_loc(col)
    if prevmean:
        print(
            "len: {}({})={}%, [{}] {} mean: {}, min: {} (diff with previous: {} and {})".format(
                len(d),
                origlen,
                percentage,
                index,
                col,
                mean,
                minimum,
                prevmean - mean,
                prevmin - minimum,
            )
        )
        prevmean = None
        prevmin = None
    else:
        print(
            "len: {}({})={}%, [{}] {} mean: {}, min: {}".format(
                len(d), origlen, percentage, index, col, mean, minimum
            )
        )
        prevmean = mean
        prevmin = minimum
    # axis = sns.rugplot([mean], height=0.1, ax=axis, color=colors[i])

    if "MINOR" in col:
        axis = sns.rugplot(
            [data[col][int(origlen / 100)]], ax=axis, height=0.2, color=colors[i]
        )

axis.autoscale()

plt.xlabel("Reference clock-cycles")
plt.ylabel("Density")
plt.title(title)
plt.gcf().set_size_inches(w=5.1, h=2.5)
plt.legend()
plt.show()

if writetofile:
    plt.savefig(pgfoutputname, bbox_inches="tight")
    print("Output printed to " + pgfoutputname)
