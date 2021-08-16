#!/usr/bin/env python3
# ------------------------------------------------------------------
#
#  Copyright (C) 2013-2020 Canonical Ltd.
#  Authors: Steve Beattie <steve.beattie@canonical.com>
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of version 2 of the GNU General Public
#  License published by the Free Software Foundation.
#
#  Simple test script for checking for errors and warnings emitted by
#  the apparmor parser.
#
# ------------------------------------------------------------------

from argparse import ArgumentParser
import os
import unittest
import subprocess
import testlib

config = None

class AAErrorTests(testlib.AATestTemplate):
    def setUp(self):
        self.maxDiff = None
        self.cmd_prefix = [config.parser, '--config-file=./parser.conf', '-S', '-I', 'errors']

    def _run_test(self, profile, message='', is_error=True):
        cmd = self.cmd_prefix + [profile]

        (rc, out, outerr) = self._run_cmd(cmd, stdout=subprocess.DEVNULL)
        report = "\nCommand: %s\nExit value:%s\nSTDERR\n%s" % (" ".join(cmd), rc, outerr)
        if is_error:
            self.assertNotEqual(rc, 0, report)
        else:
            self.assertEqual(rc, 0, report)

        ignore_messages = [
            'Cache read/write disabled: interface file missing. (Kernel needs AppArmor 2.4 compatibility patch.)\n',
        ]
        for ign in ignore_messages:
            if ign in outerr:
                outerr = outerr.replace(ign, '')

        self.assertEqual(message, outerr, report)

    def test_okay(self):
        self._run_test('errors/okay.sd', is_error=False)

    def test_single(self):
        self._run_test(
            'errors/single.sd',
            "AppArmor parser error for errors/single.sd in profile errors/single.sd at line 3: Could not open 'failure'\n",
        )

    def test_double(self):
        self._run_test(
            'errors/double.sd',
            "AppArmor parser error for errors/double.sd in profile errors/includes/busted at line 66: Could not open 'does-not-exist'\n",
        )

    def test_modefail(self):
        self._run_test(
            'errors/modefail.sd',
            "AppArmor parser error for errors/modefail.sd in profile errors/modefail.sd at line 6: syntax error, unexpected TOK_ID, expecting TOK_MODE\n",
        )

    def test_multi_include(self):
        self._run_test(
            'errors/multi_include.sd',
            "AppArmor parser error for errors/multi_include.sd in profile errors/multi_include.sd at line 12: Could not open 'failure'\n",
        )

    def test_deprecation1(self):
        self.cmd_prefix.extend(['--warn=deprecated'])
        self._run_test(
            'errors/deprecation1.sd',
            "Warning from errors/deprecation1.sd (errors/deprecation1.sd line 6): The use of file paths as profile names is deprecated. See man apparmor.d for more information\n",
            is_error=False
        )

    def test_deprecation2(self):
        self.cmd_prefix.extend(['--warn=deprecated'])
        self._run_test(
            'errors/deprecation2.sd',
            "Warning from errors/deprecation2.sd (errors/deprecation2.sd line 6): The use of file paths as profile names is deprecated. See man apparmor.d for more information\n",
            is_error=False
        )


def main():
    rc = 0

    global config
    p = ArgumentParser()
    p.add_argument('-p', '--parser', default=testlib.DEFAULT_PARSER, action="store", dest='parser',
                   help="Specify path of apparmor parser to use [default = %(default)s]")
    p.add_argument('-v', '--verbose', action="store_true", dest="verbose")
    config = p.parse_args()

    verbosity = 1
    if config.verbose:
        verbosity = 2

    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AAErrorTests))
    try:
        result = unittest.TextTestRunner(verbosity=verbosity).run(test_suite)
        if not result.wasSuccessful():
            rc = 1
    except:
        rc = 1

    return rc


if __name__ == "__main__":
    exit(main())
