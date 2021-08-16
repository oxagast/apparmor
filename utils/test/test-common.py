#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest
from common_test import AATest, setup_all_loops
from apparmor.common import AppArmorBug

from apparmor.common import type_is_str, split_name, combine_profname

class TestIs_str_type(AATest):
    tests = [
        ('foo',     True),
        (u'foo',    True),
        (42,        False),
        (True,      False),
        ([],        False),
    ]

    def _run_test(self, params, expected):
        self.assertEqual(type_is_str(params), expected)

class AaTest_split_name(AATest):
    tests = [
        # full profile name                 expected parts
        ('foo',                             ('foo',             'foo')),
        ('foo//bar',                        ('foo',             'bar')),
        ('foo//bar//baz',                   ('foo',             'bar')),  # XXX nested child profiles get cut off
    ]

    def _run_test(self, params, expected):
        self.assertEqual(split_name(params), expected)

class AaTest_combine_profname(AATest):
    tests = [
        # name parts                        expected full profile name
        (['foo'],                           'foo'),
        (['foo', 'bar'],                    'foo//bar'),
        (['foo', 'bar', 'baz'],             'foo//bar//baz'),
        (['foo', 'bar', None],              'foo//bar'),
        (['foo', 'bar', 'baz', None],       'foo//bar//baz'),
    ]

    def _run_test(self, params, expected):
        self.assertEqual(combine_profname(params), expected)

    def test_wrong_type(self):
        with self.assertRaises(AppArmorBug):
            combine_profname('foo')


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
