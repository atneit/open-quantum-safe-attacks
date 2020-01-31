import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from pandas.core.algorithms import value_counts

if len(sys.argv) < 4:
    print("Usage: data.csv tail% COLUMN1 [COLUMN2 [COLUMN3 [...]]]")
    sys.exit(1)
    
csvname = sys.argv[1]
samplesize = int(sys.argv[2])
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
    return d[0:last][d < maxval]#.sample(samplesize)

colors = [(255,0,0,255)]

axis = None
height = 0
for col in columns:
    height += 0.05
    d = usecol(col)
    axis = sns.distplot(d, label=col, kde=True, bins=200, ax=axis)
    #axis = sns.kdeplot(d, label=col, cut=0, ax=axis)
    mean = d.mean()
    print("{} mean: {}".format(col, mean))
    axis = sns.rugplot([mean], ax=axis, height=height)

axis.autoscale()

plt.legend()
plt.show()