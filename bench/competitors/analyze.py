#!/usr/bin/env python3
"""Derive phase medians from retained raw trials without modifying that evidence."""
import argparse
import csv
import json
from pathlib import Path
import statistics
import sys

parser = argparse.ArgumentParser()
parser.add_argument('results', type=Path)
args = parser.parse_args()
records = [json.loads(line) for line in (args.results/'raw.jsonl').read_text().splitlines()]
if not records or not all(record['valid'] for record in records):
    raise SystemExit('Incomplete or invalid correctness evidence')
writer = csv.writer(sys.stdout)
writer.writerow(['workload', 'case', 'tool', 'runs', 'median_command_ms',
                 'median_external_flush_ms', 'median_verification_ms',
                 'median_completion_ms', 'min_completion_ms', 'max_completion_ms'])
groups = sorted({(r['workload'], r['case'], r['tool']) for r in records})
for key in groups:
    group = [r for r in records if not r['warmup'] and (r['workload'], r['case'], r['tool']) == key]
    if not group:
        continue
    for r in group:
        if abs(r['completion_s'] - (r['transfer']['wall_s'] + r['barrier']['wall_s'] + r['verification_s'])) > 1e-9:
            raise SystemExit('Inconsistent recorded phase arithmetic')
    ms = lambda values: round(statistics.median(values)*1000, 6)
    writer.writerow([*key, len(group), ms(r['transfer']['wall_s'] for r in group),
                     ms(r['barrier']['wall_s'] for r in group), ms(r['verification_s'] for r in group),
                     ms(r['completion_s'] for r in group),
                     round(min(r['completion_s'] for r in group)*1000, 6),
                     round(max(r['completion_s'] for r in group)*1000, 6)])
