#!/usr/bin/env python3

import json
import csv

with open('scoreboard-filtered.csv', 'r') as fin:
    csvreader = csv.reader(fin)
    res = []
    next(csvreader)
    for idx, line in enumerate(csvreader):
        res.append({'pos': idx+1, 'team': line[0], 'score': line[1]})

with open('scoreboard.json', 'w') as fout:
    json.dump({'standings': res}, fout)
