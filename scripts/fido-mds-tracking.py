#!/usr/bin/env python3
"""Verify the live feed, then update one tracking issue only for a newer serial."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

import fido_mds

TITLE = 'FIDO MDS verified feed refresh (scheduled tracking)'
MARKER = '<!-- fido-mds-refresh -->'


def gh(*args):
    return subprocess.run(['gh', *args], check=True, capture_output=True, text=True).stdout


def track(repo, report):
    if report['feed']['blob_number'] <= report['previous_serial']:
        return
    # Search all states with pagination: a closed tracking issue is reopened, never duplicated.
    pages = json.loads(gh('api', '--paginate', '--slurp', f'repos/{repo}/issues?state=all&per_page=100'))
    matches = [issue for page in pages for issue in page
               if 'pull_request' not in issue and issue['title'] == TITLE and MARKER in (issue['body'] or '')]
    if len(matches) > 1:
        raise ValueError('multiple tracking issues; resolve duplicates before refreshing')
    body = (f'{MARKER}\nVerified newer FIDO MDS feed; review and apply this exact lock change.\n\n'
            + report['verification'] + '\n\n'
            + 'Evidence:\n```json\n' + json.dumps({k: v for k, v in report.items() if k != 'patch'}, indent=2)
            + '\n```\n\n```diff\n' + report['patch'] + '```\n\n'
            + 'No lock was written. Re-run verification before applying; upstream is mutable.\n')
    with tempfile.TemporaryDirectory() as tmp:
        file = Path(tmp) / 'body.md'
        file.write_text(body)
        if matches:
            issue = matches[0]
            if issue['body'] != body:
                gh('issue', 'edit', str(issue['number']), '--repo', repo, '--body-file', str(file))
            if issue['state'] == 'closed':
                gh('issue', 'reopen', str(issue['number']), '--repo', repo)
        else:
            print(gh('issue', 'create', '--repo', repo, '--title', TITLE, '--body-file', str(file)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True)
    args = parser.parse_args()
    # A subprocess runs the very same verifier as acquisition. No issue mutation
    # happens unless the complete verification and cross-architecture comparison succeed.
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / 'report.json'
        subprocess.run(['python3', str(Path(__file__).with_name('fido_mds.py')), 'report',
                        '--crl-dir', str(Path(tmp) / 'crls'), '--fetch-crls', '--output', str(report)], check=True)
        track(args.repo, json.loads(report.read_text()))


if __name__ == '__main__':
    main()
