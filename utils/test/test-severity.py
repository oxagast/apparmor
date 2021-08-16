#!/usr/bin/python3
# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2014 Canonical, Ltd.
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# ----------------------------------------------------------------------
import unittest
from common_test import AATest, setup_all_loops

import apparmor.severity as severity
from apparmor.common import AppArmorException

class SeverityBaseTest(AATest):

    def AASetup(self):
        self.sev_db = severity.Severity('../severity.db', 'unknown')

    def _capability_severity_test(self, cap, expected_rank):
        rank = self.sev_db.rank_capability(cap)
        self.assertEqual(rank, expected_rank,
                         'expected rank %s, got %s' % (expected_rank, rank))

    def _simple_severity_w_perm(self, path, perm, expected_rank):
        rank = self.sev_db.rank_path(path, perm)
        self.assertEqual(rank, expected_rank,
                         'expected rank %s, got %s' % (expected_rank, rank))

class SeverityTest(SeverityBaseTest):
    tests = [
        (['/usr/bin/whatis',    'x'     ],  5),
        (['/etc',               'x'     ],  'unknown'),
        (['/dev/doublehit',     'x'     ],  0),
        (['/dev/doublehit',     'rx'    ],  4),
        (['/dev/doublehit',     'rwx'   ],  8),
        (['/dev/tty10',         'rwx'   ],  9),
        (['/var/adm/foo/**',    'rx'    ],  3),
        (['/etc/apparmor/**',   'r'     ],  6),
        (['/etc/**',            'r'     ],  'unknown'),
        (['/usr/foo@bar',       'r'     ],  'unknown'),  ## filename containing @
        (['/home/foo@bar',      'rw'    ],  6),  ## filename containing @
        (['/etc/apache2/ssl.key/bar',       'r'   ],  7),  # /etc/apache2/** (3) vs. /etc/apache2/**ssl** (7)
        (['/etc/apache2/foo/ssl/bar',       'r'   ],  7),  # additional path level triggers otherwise untested branch
        (['/proc/sys/kernel/hotplug',       'rwx' ], 10),  # non-glob filename, severity depends on mode
    ]

    def _run_test(self, params, expected):
        self._simple_severity_w_perm(params[0], params[1], expected)  ## filename containing @

    def test_invalid_rank(self):
        with self.assertRaises(AppArmorException):
            self._simple_severity_w_perm('unexpected_unput', 'rw', 6)

class SeverityTestCap(SeverityBaseTest):
    tests = [
        ('KILL', 8),
        ('SETPCAP', 9),
        ('setpcap', 9),
        ('UNKNOWN', 'unknown'),
        ('K*', 'unknown'),
        ('__ALL__', 10),
    ]

    def _run_test(self, params, expected):
        self._capability_severity_test(params, expected)

        rank = self.sev_db.rank_capability(params)
        self.assertEqual(rank, expected, 'expected rank %s, got %s' % (expected, rank))


class SeverityVarsTest(SeverityBaseTest):
    tests = [
        (['@{PROC}/sys/vm/overcommit_memory',           'r'],    6),
        (['@{HOME}/sys/@{PROC}/overcommit_memory',      'r'],    4),
        (['/overco@{multiarch}mmit_memory',             'r'],    'unknown'),
        (['@{PROC}/sys/@{TFTP_DIR}/overcommit_memory',  'r'],    6),
        (['@{somepaths}/somefile',                      'r'],    7),
        (['@{strangevar}/somefile',                     'r'],    6),
    ]

    def _run_test(self, params, expected):
        vars = {
            '@{HOME}':      {'@{HOMEDIRS}/*/', '/root/'},
            '@{HOMEDIRS}':  {'/home/', '/storage/'},
            '@{multiarch}': {'*-linux-gnu*'},
            '@{TFTP_DIR}':  {'/var/tftp /srv/tftpboot'},
            '@{PROC}':      {'/proc/'},
            '@{somepaths}': {'/home/foo/downloads', '@{HOMEDIRS}/foo/.ssh/'},
            '@{strangevar}': ['/srv/', '/proc/'],  # Note: using [] instead of {} is intentional to keep order of checking (and therefore code coverage) constant
        }
        self.sev_db.set_variables(vars)
        self._simple_severity_w_perm(params[0], params[1], expected)

class SeverityDBTest(AATest):
    def _test_db(self, contents):
        self.db_file = self.writeTmpfile('severity.db', contents)
        self.sev_db = severity.Severity(self.db_file)
        return self.sev_db

    tests = [
        ("CAP_LEASE 18\n"               , AppArmorException),  # out of range
        ("CAP_LEASE -1\n"               , AppArmorException),  # out of range
        ("/etc/passwd* 0 4\n"           , AppArmorException),  # insufficient vals
        ("/etc/passwd* 0 4 5 6\n"       , AppArmorException),  # too many vals
        ("/etc/passwd* -2 4 6\n"        , AppArmorException),  # out of range
        ("/etc/passwd* 12 4 6\n"        , AppArmorException),  # out of range
        ("/etc/passwd* 2 -4 6\n"        , AppArmorException),  # out of range
        ("/etc/passwd 2 14 6\n"         , AppArmorException),  # out of range
        ("/etc/passwd 2 4 -12\n"        , AppArmorException),  # out of range
        ("/etc/passwd 2 4 4294967297\n" , AppArmorException),  # out of range
        ("garbage line\n"               , AppArmorException),
    ]

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            self._test_db(params)

    def test_simple_db(self):
        self._test_db('''
    CAP_LEASE 8
    /etc/passwd*    4 8 0
''')

    def test_cap_val_max_range(self):
        self._test_db("CAP_LEASE 10\n")

    def test_cap_val_min_range(self):
        self._test_db("CAP_LEASE 0\n")

    def test_invalid_db(self):
        self.assertRaises(AppArmorException, severity.Severity, 'severity_broken.db')

    def test_nonexistent_db(self):
        self.assertRaises(IOError, severity.Severity, 'severity.db.does.not.exist')

    def test_no_arg_to_severity(self):
        with self.assertRaises(AppArmorException):
            severity.Severity()

setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
