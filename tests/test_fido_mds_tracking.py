"""Tracking issues are deduplicated and mutations follow successful verification."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path('scripts').resolve()))
SPEC = importlib.util.spec_from_file_location('tracking', Path('scripts/fido-mds-tracking.py'))
TRACK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRACK)

REPORT = {'previous_serial': 301, 'feed': {'blob_number': 302}, 'verification': 'verified', 'patch': 'diff\n'}


class TrackingTests(unittest.TestCase):
    def test_unchanged_does_not_touch_issues(self):
        with mock.patch.object(TRACK, 'gh') as gh:
            TRACK.track('owner/repo', dict(REPORT, previous_serial=302))
        gh.assert_not_called()

    def test_new_serial_creates_one_issue(self):
        with mock.patch.object(TRACK, 'gh', side_effect=['[[]]', 'issue-url']) as gh:
            TRACK.track('owner/repo', REPORT)
        self.assertEqual(gh.call_count, 2)
        self.assertEqual(gh.call_args.args[:2], ('issue', 'create'))

    def test_closed_issue_is_updated_and_reopened(self):
        issue = {'number': 7, 'title': TRACK.TITLE, 'body': TRACK.MARKER, 'state': 'closed'}
        with mock.patch.object(TRACK, 'gh', side_effect=[json.dumps([[issue]]), '', '']) as gh:
            TRACK.track('owner/repo', REPORT)
        self.assertEqual([c.args[:2] for c in gh.call_args_list[1:]],
                         [('issue', 'edit'), ('issue', 'reopen')])

    def test_duplicate_tracking_issues_fail_closed(self):
        issue = {'number': 7, 'title': TRACK.TITLE, 'body': TRACK.MARKER, 'state': 'open'}
        with mock.patch.object(TRACK, 'gh', return_value=json.dumps([[issue, issue]])) as gh:
            with self.assertRaises(ValueError):
                TRACK.track('owner/repo', REPORT)
        self.assertEqual(gh.call_count, 1)

    def test_failed_verifier_cannot_mutate_issue(self):
        with mock.patch.object(sys, 'argv', ['tracking', '--repo', 'owner/repo']), \
                mock.patch.object(TRACK.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'verify')), \
                mock.patch.object(TRACK, 'track') as track:
            with self.assertRaises(subprocess.CalledProcessError):
                TRACK.main()
        track.assert_not_called()
