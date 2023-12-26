#!/usr/bin/env python3

import csv
import sys

with open(sys.argv[1], 'r') as fin:
    csvreader = csv.reader(fin)
    for line in csvreader:
        print(f'"{line[0]} {line[1]}",')
