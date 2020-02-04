import sys

import matplotlib
matplotlib.use("pgf")
matplotlib.rcParams.update({
    "pgf.texsystem": "pdflatex",
    'font.family': 'serif',
    'text.usetex': True,
    'pgf.rcfonts': False,
    'font.size': 8,
})

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from pandas.core.algorithms import value_counts


if len(sys.argv) < 4:
    print("Usage: data.csv output.pgf maximum-value COLUMN1 [COLUMN2 [COLUMN3 [...]]]")
    sys.exit(1)
    
csvname = sys.argv[1]
pgfoutputname = sys.argv[2]
#samplesize = int(sys.argv[2])
percentage = 1.0#0.75  #float(sys.argv[3]) / 100
maxval = int(sys.argv[3])
colspec = sys.argv[4:]


data = pd.read_csv(csvname, sep=',', header=0)

columns = []
for spec in colspec:
    for col in data.columns:
        if spec in col and col not in columns:
            columns.append(col)
            
print("Selected columns: " + repr(columns))

def usecol(col):
    d = data[col]
    last = int(len(d) * percentage)
    return d[0:last][d < maxval]  #.sample(samplesize)
    

def getlabel(colname):
    if "NOMOD" in colname:
        return "$x=0$"
    elif "MINOR" in colname:
        return "$x=1$"
    elif "MAJOR" in colname:
        return "$x=2^{D-B}$"
    else:
        return colname


colors = ["r", "g", "b"]

axis = None
height = 0.25
prevmean = None
for (i, col) in enumerate(columns):
    height -= 0.05
    d = usecol(col)
    axis = sns.distplot(d, label=getlabel(col), kde=True, bins=40, ax=axis, kde_kws={'cut':0}, color=colors[i])
    #axis = sns.kdeplot(d, label=col, cut=0, ax=axis, color=colors[i])
    mean = d.mean()
    if prevmean:
        print("{} mean: {} (diff with previous: {})".format(col, mean, prevmean - mean))
        prevmean = None
    else:
        print("{} mean: {}".format(col, mean))
        prevmean = mean
    axis = sns.rugplot([mean], height=height, ax=axis, color=colors[i])

axis.autoscale()

plt.xlabel("Reference clock-cycles")
plt.ylabel("KDE")
#plt.title("MEMCMP")
plt.gcf().set_size_inches(w=5, h=1.75)
plt.legend()
plt.show()

plt.savefig(pgfoutputname, bbox_inches = 'tight')
print("Output printed to " + pgfoutputname)