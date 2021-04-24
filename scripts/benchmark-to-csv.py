#!/usr/bin/env python

import sys
import csv

from collections import defaultdict
from io import StringIO

def parse_line(line):
    path, result = line.strip().split(': ')

    scheme, backend, degree, *measure = path.split('/')

    value, unit = result.split(' ')
    value = int(value)

    return (scheme, backend, degree), tuple(measure), (value, unit)

def main():
    rows = defaultdict(dict)
    fields = set()

    for params, measure, (result, unit) in map(parse_line, sys.stdin):
        if measure[-1] == 'ops':
            continue

        scheme, backend, degree = params
        rows[params]['scheme'] = scheme
        rows[params]['backend'] = backend
        rows[params]['degree'] = degree

        if measure[0] == 'vector size':
            rows[params]['vector size'] = result
            continue

        field = f'{measure[0]} ({unit})'
        fields.add(field)
        rows[params][field] = result

    fields = ['scheme', 'backend', 'degree', 'vector size'] + sorted(fields)
    f = StringIO()
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(list(rows.values()))

    print(f.getvalue())

if __name__ == '__main__':
    exit(main())
