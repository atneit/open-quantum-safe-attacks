import sys

if len(sys.argv) < 4:
    print("Usage: data.csv tail% COLUMN1 [COLUMN2 [COLUMN3 [...]]]")
    sys.exit(1)
    
csvname = sys.argv[1]
percentage = float(sys.argv[2]) / 100
columns = sys.argv[3:]

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

data = pd.read_csv(csvname, sep=',', header=0)

def usecol(col):
    d = data[col]
    last = int(len(d) * percentage)
    return d[0:last]


axis = None
for col in columns:
    d = usecol(col)
    axis = sns.kdeplot(d, label=col, cut=0, ax=axis)
    axis = sns.rugplot(d[0:1], ax=axis)

axis.autoscale()

plt.legend()
plt.show()