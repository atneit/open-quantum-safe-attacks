#!/bin/env python3

from ast import parse
import re
from pandas.core.algorithms import value_counts
import pandas as pd
import numpy as np
import sys
import gc
import itertools as IT

from pandas.core.frame import DataFrame
from seaborn.external.docscrape import header

def parseargs():
    import argparse

    parser = argparse.ArgumentParser(description='Process a multipoint datafile')
    #parser.add_argument('-p', '--percentage', type=float, nargs='?', default=100.0)
    parser.add_argument('-x', '--max', type=int, nargs='?', default=sys.maxsize)
    parser.add_argument('-n', '--min', type=int, nargs='?', default=0)
    parser.add_argument('-a', "--auto-cut", action='store_true')
    parser.add_argument('-d', "--delete-output", action='store_true')
    parser.add_argument('-c', "--chunksize", type=int, nargs='?', default=10**5)
    parser.add_argument('INPUT')
    parser.add_argument('OUTPUT')
    parser.add_argument('COLSPEC', nargs='+')


    args = parser.parse_args()
    print(repr(args))

    return args


def select_columns(csvname, colspec):
    shape = pd.read_csv(csvname, sep=',', header=0, nrows=1)

    selected_columns = set()
    for column in shape:
        add = False
        for spec in colspec:
            if spec in column:
                selected_columns.add(column)

    return sorted(selected_columns)


def parsecolumnname(column):
    parts = column.split("-")
    try:
        try:
            keynum = parts[0]
            ciphertext = parts[1]
            target = parts[2]
            modified = parts[3]
        except:
            keynum = parts[0]
            ciphertext = parts[1]
            target = "all"
            modified = parts[2]
    except:
        keynum = 1
        ciphertext = parts[0]
        target = "all"
        modified = parts[1]
    
    modified = modified != "MINOR" and modified != "NOMOD"

    return keynum, ciphertext, target, modified

def valid(chunks, column, minval, maxval):
    for chunk in chunks:
        mask = ((chunk[column] < maxval) & (chunk[column] > minval))
        if mask.all():
            yield chunk[column]
        else:
            yield chunk[column].loc[mask]
            break


def Main():
    args = parseargs()

    print("Reading from " + args.INPUT)

    selected_columns = select_columns(args.INPUT, args.COLSPEC)

    if args.delete_output:
        print("Truncating existing data in " + args.OUTPUT)
        headers = pd.DataFrame(
            columns=["clock cycles", "keynum", "ciphertext", "target", "modified"])
            
        headers.to_csv(args.OUTPUT, index = False, header=True)

    target_maxvalue = {}

    for column in selected_columns:

        keynum, ciphertext, target, modified = parsecolumnname(column)
        print("Appending to {} with keynum={}, ciphertext={}, target={}, modified={} ".format(
            args.OUTPUT, keynum, ciphertext, target, modified), end="", flush=True)

        chunks = pd.read_csv(args.INPUT, usecols=[column], chunksize=args.chunksize)

        first_std = None
        autocut = False

        if not target in target_maxvalue:
            maxvalue = args.max
            autocut = args.auto_cut
        else:
            maxvalue = target_maxvalue[target]
        
        for chunk in valid(chunks, column, args.min, maxvalue):
            print(".", end="", flush=True)

            data = pd.DataFrame(chunk)
            
            data.rename({column: "clock cycles"}, axis=1, inplace=True)
            
            data["keynum"] = keynum
            data["ciphertext"] = ciphertext
            data["target"] = target
            data["modified"] = modified

            numeric_cols=data.columns.drop('target')
            data[numeric_cols]=data[numeric_cols].apply(pd.to_numeric)

            last_chunk = False
            if autocut and not target in target_maxvalue:
                std = data["clock cycles"].std()
                if not first_std:
                    first_std = std
                if std > first_std:
                    last_chunk = True
                    maxval = data["clock cycles"].iloc[-1]
                    target_maxvalue[target] = maxval
                    print(" target_maxval[{}] = {}".format(target, maxval), end="")

            if last_chunk:
                del data
                break
            else:
                data.to_csv(args.OUTPUT, index = False, mode = 'a', header = False)
                del data
        print("")

    print("Done")


if __name__ == "__main__":
    Main()
