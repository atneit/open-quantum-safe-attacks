#!/usr/bin/env python3

import sys
import re

reg_cipher_number = re.compile(r"Using encaps to generate ciphertext number: (\d+)")
reg_start = re.compile(r"Starting binary search (\d)/3 for Eppp\[(\d,\d)\], expect to find x0 = (\d+)")
reg_test = re.compile(r"C\[\d\d\/\d\d\] => Testing adding (\d+) to C\[\d\d\] with (\d+) iterations.")
reg_bad_profile = re.compile(r"threshold high \(.*\) <=  LOW_PERCENTAGE_LIMIT \(.*\)")
reg_limit_search = re.compile(r"Percentage of values below limit for (?:high|low) amount of modifications")
reg_lowering_limit = re.compile(r"C\[\d\d\/\d\d\] => (?:-Lowering upperbound to|Confirmed upperbound) (\d+)")
reg_raising_limit = re.compile(r"C\[\d\d\/\d\d\] => (?:\+Raising lowerbound to|Confirmed lowerbound) (\d+)")
reg_conflicting = re.compile(r"Conflicting results for upperbound (\d+)")
reg_outside_range = re.compile(r"percentage [\d\.]+ outside of expected ranges:")

filename = sys.argv[1]

matches = {}

def search(line, reg, matches, keys):
    res = reg.search(line)
    if res:
        for (k, g) in zip(keys, res.groups()):
            matches[k] = g
        return True
    return False


handled_test = True
with open(filename) as f:
    for line in f.readlines():
        line = line.strip()
        reg_cipher_number.search(line)
        search(line, reg_cipher_number, matches, ['cipher_number'])
        if search(line, reg_start, matches, ['attempt', 'index', 'expected_x0']):
            print("new attempt: {attempt}/3 expect: {expected_x0}".format(**matches))
        if search(line, reg_limit_search, matches, []):
            if int(matches['test']) == 1 or int(matches['test']) == 4095:
                handled_test = True
        if search(line, reg_test, matches, ['test', 'iterations']):
            if not handled_test:
                print(line)
                sys.exit(1)
            handled_test = False
        if search(line, reg_bad_profile, matches, []):
            handled_test = True
            print("bad profile for {cipher_number}:{index}#{attempt}".format(**matches))
        if search(line, reg_lowering_limit, matches, ['upper_limit']):
            handled_test = True
            good_decision = int(matches['expected_x0']) <= int(matches['upper_limit'])
            if not good_decision:
                print(line)
            else:
                print("Good + decision")
        if search(line, reg_raising_limit, matches, ['lower_limit']):
            handled_test = True
            good_decision = int(matches['expected_x0']) > int(matches['lower_limit'])
            if not good_decision:
                print(line)
            else:
                print("Good - decision")
        if search(line, reg_outside_range, matches, []):
            handled_test = True
            print("inconclusive")
        