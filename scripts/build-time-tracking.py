#!/usr/bin/env python3
"""Keep the build-time audit tracking issue current. Comments only when the finding set changes."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

TITLE = 'Build-time dependency vulnerabilities (scheduled tracking)'
MARKER = re.compile(r'<!-- build-time-audit fingerprint=([0-9a-f]{64}) -->')


def gh(*args):
    return subprocess.run(['gh', *args], check=True, text=True, capture_output=True).stdout


def latest_fingerprint(texts):
    """The newest recorded fingerprint wins; texts are oldest first (issue body, then comments)."""
    found = [m for text in texts for m in MARKER.findall(text or '')]
    return found[-1] if found else None


def decide(issue, texts, fingerprint):
    if issue is None:
        return 'create'
    return 'unchanged' if latest_fingerprint(texts) == fingerprint else 'comment'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', required=True)
    parser.add_argument('--summary', required=True, type=Path)
    parser.add_argument('--markdown', required=True, type=Path)
    parser.add_argument('--run-url', required=True)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    fingerprint = json.loads(args.summary.read_text(encoding='utf-8'))['fingerprint']
    report = args.markdown.read_text(encoding='utf-8')
    if len(report) > 60000:  # GitHub caps issue bodies and comments at 65536 characters.
        report = report[:60000] + '\n\n(Truncated; the full table is in the run summary and artifact.)\n'
    body = (report + f'\nSource run: {args.run_url}\n\n'
            f'<!-- build-time-audit fingerprint={fingerprint} -->\n')
    issues = json.loads(gh('issue', 'list', '--repo', args.repo, '--state', 'open', '--limit', '100',
                           '--search', f'"{TITLE}" in:title', '--json', 'number,title'))
    matching = sorted(i['number'] for i in issues if i['title'] == TITLE)
    issue = matching[0] if matching else None
    texts = []
    if issue is not None:
        view = json.loads(gh('issue', 'view', str(issue), '--repo', args.repo, '--json', 'body,comments'))
        texts = [view['body']] + [c['body'] for c in view['comments']]
    action = decide(issue, texts, fingerprint)
    print(f'tracking issue: {issue or "none"}; fingerprint {fingerprint}; action: {action}'
          + (' (dry run)' if args.dry_run else ''))
    if args.dry_run or action == 'unchanged':
        return 0
    if action == 'create':
        intro = ('Non-blocking report from the scheduled CI run. The blocking image gate is separate. '
                 'A comment is added only when the build-time finding set changes.\n\n')
        print(gh('issue', 'create', '--repo', args.repo, '--title', TITLE, '--body', intro + body).strip())
    else:
        print(gh('issue', 'comment', str(issue), '--repo', args.repo, '--body', 'Finding set changed.\n\n' + body).strip())
    return 0


if __name__ == '__main__':
    sys.exit(main())
