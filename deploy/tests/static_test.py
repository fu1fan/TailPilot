#!/usr/bin/env python3
"""Portable unit grammar checks, NOT systemd-analyze/native acceptance."""
import configparser
from pathlib import Path
import shlex
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import native_test


class UnitSyntaxTests(unittest.TestCase):
    def test_concrete_boot_and_dependency_grammar(self):
        fixture = native_test.NativeTests()
        fixture.setUp()
        try:
            fixture.arm()
            unit=fixture.h.path('/etc/systemd/system/'+fixture.t.boot)
            cp=configparser.ConfigParser(interpolation=None, strict=True)
            cp.optionxform=str
            cp.read(unit)
            self.assertEqual(set(cp.sections()), {'Unit','Service'})
            self.assertEqual(cp['Unit']['Before'], 'tailscaled.service')
            self.assertEqual(cp['Service']['Type'],'oneshot')
            self.assertEqual(cp['Service']['RemainAfterExit'],'yes')
            self.assertEqual(shlex.split(cp['Service']['ExecStart']),fixture.t.argv('boot'))
            self.assertEqual(int(cp['Service']['TimeoutStartSec']),180)
            guard=configparser.ConfigParser(interpolation=None);guard.optionxform=str
            guard.read(fixture.t.guard)
            self.assertEqual(guard['Unit']['Requires'],fixture.t.boot)
            self.assertEqual(guard['Unit']['After'],fixture.t.boot)
            self.assertNotIn('@',unit.read_text())
        finally:
            fixture.doCleanups()


if __name__=='__main__': unittest.main()
