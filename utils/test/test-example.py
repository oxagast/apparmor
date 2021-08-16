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
from common_test import AATest, setup_all_loops # , setup_aa
# import apparmor.aa as aa  # see the setup_aa() call for details

class TestFoo(AATest):
    tests = [
        (0,  0 ),
        (42, 42),
    ]

    def _run_test(self, params, expected):
        self.assertEqual(params, expected)

class TestBar(AATest):
    tests = [
        ('a', 'foo'),
        ('b', 'bar'),
        ('c', 'baz'),
    ]

    def _run_test(self, params, expected):
        self.assertNotEqual(params, expected)

    def testAdditionalBarTest(self):
        self.assertEqual(1, 1)

class TestBaz(AATest):
    def AASetup(self):
        # called by setUp() - use AASetup() to avoid the need for using super(...)
        pass

    def AATeardown(self):
        # called by tearDown() - use AATeardown() to avoid the need for using super(...)
        pass

    def test_Baz_only_one_test(self):
        self.assertEqual("baz", "baz")

# if you import apparmor.aa and call init_aa() in your tests, uncomment this
# setup_aa(aa)
setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
