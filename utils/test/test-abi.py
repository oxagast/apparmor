#!/usr/bin/python3
# ----------------------------------------------------------------------
#    Copyright (C) 2020 Christian Boltz <apparmor@cboltz.de>
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
from collections import namedtuple
from common_test import AATest, setup_all_loops

from apparmor.rule.abi import AbiRule, AbiRuleset
#from apparmor.rule import BaseRule
from apparmor.common import AppArmorException, AppArmorBug
#from apparmor.logparser import ReadLog
from apparmor.translations import init_translation
_ = init_translation()

exp = namedtuple('exp', [ # 'audit', 'allow_keyword', 'deny',
        'comment',
        'path', 'ifexists', 'ismagic'])

# --- tests for single AbiRule --- #

class AbiTest(AATest):
    def _compare_obj(self, obj, expected):
        self.assertEqual(False, obj.allow_keyword)  # not supported in abi rules, expected to be always False
        self.assertEqual(False, obj.audit)          # not supported in abi rules, expected to be always False
        self.assertEqual(False, obj.deny)           # not supported in abi rules, expected to be always False
        self.assertEqual(expected.comment, obj.comment)

        self.assertEqual(expected.path, obj.path)
        self.assertEqual(False, expected.ifexists)  # tests bug - should always expect ifexists==False
        self.assertEqual(False, obj.ifexists)       # not supported in abi rules, expected to be always False
        self.assertEqual(expected.ismagic, obj.ismagic)

class AbiTestParse(AbiTest):
    tests = [
        # AbiRule object                                        comment             path                       if exists   ismagic
        ('abi <abstractions/base>,',                        exp('',                 'abstractions/base',       False,      True )),  # magic path
        ('abi <abstractions/base>, # comment',              exp(' # comment',       'abstractions/base',       False,      True )),
        ('abi<abstractions/base>,#comment',                 exp(' #comment',        'abstractions/base',       False,      True )),
        ('   abi     <abstractions/base> , ',               exp('',                 'abstractions/base',       False,      True )),
        ('abi "/foo/bar",',                                 exp('',                 '/foo/bar',                False,      False)),  # absolute path
        ('abi "/foo/bar", # comment',                       exp(' # comment',       '/foo/bar',                False,      False)),
        ('abi "/foo/bar",#comment',                         exp(' #comment',        '/foo/bar',                False,      False)),
        ('   abi "/foo/bar" , ',                            exp('',                 '/foo/bar',                False,      False)),
    ]

    def _run_test(self, rawrule, expected):
        self.assertTrue(AbiRule.match(rawrule))
        obj = AbiRule.parse(rawrule)
        self.assertEqual(rawrule.strip(), obj.raw_rule)
        self._compare_obj(obj, expected)

class AbiTestParseInvalid(AbiTest):
    tests = [
#       (' some abi <abstractions/base>',                       AppArmorException),
#       ('  /etc/fstab r,',                                     AppArmorException),
#       ('/usr/abi r,',                                         AppArmorException),
#       ('/abi r,',                                             AppArmorException),
    ]

    def _run_test(self, rawrule, expected):
        self.assertTrue(AbiRule.match(rawrule))  # the above invalid rules still match the main regex!
        with self.assertRaises(expected):
            AbiRule.parse(rawrule)

# class AbiTestParseFromLog(AbiTest):  # we'll never have log events for abi

class AbiFromInit(AbiTest):
    tests = [
        # AbiRule object                        ifexists    ismagic                       comment      path                    ifexists    ismagic
        (AbiRule('abi/4.19',                    False,      False)                  , exp('',          'abi/4.19',             False,      False    )),
        (AbiRule('foo',                         False,      False)                  , exp('',          'foo',                  False,      False    )),
        (AbiRule('bar',                         False,      True)                   , exp('',          'bar',                  False,      True     )),
        (AbiRule('comment',                     False,      False, comment='# cmt') , exp('# cmt',     'comment',              False,      False    )),
    ]

    def _run_test(self, obj, expected):
        self._compare_obj(obj, expected)

class InvalidAbiInit(AATest):
    tests = [
        # init params                     expected exception
        ([False,  False, False  ]    , AppArmorBug), # wrong type for path
        (['',     False, False  ]    , AppArmorBug), # empty path
        ([None,   False, False  ]    , AppArmorBug), # wrong type for path
#       (['    ', False, False  ]    , AppArmorBug), # whitespace-only path
        (['foo',  None,  False  ]    , AppArmorBug), # wrong type for ifexists
        (['foo',  '',    False  ]    , AppArmorBug), # wrong type for ifexists
        (['foo',  False, None   ]    , AppArmorBug), # wrong type for ismagic
        (['foo',  False, ''     ]    , AppArmorBug), # wrong type for ismagic
        (['',     True,  False  ]    , AppArmorBug), # ifexists set
    ]

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            AbiRule(params[0], params[1], params[2])

    def test_missing_params_1(self):
        with self.assertRaises(TypeError):
            AbiRule()

    def test_missing_params_2(self):
        with self.assertRaises(TypeError):
            AbiRule('foo')

    def test_missing_params_3(self):
        with self.assertRaises(TypeError):
            AbiRule('foo', False)

    def test_audit_true(self):
        with self.assertRaises(AppArmorBug):
            AbiRule('foo', False, False, audit=True)

    def test_deny_true(self):
        with self.assertRaises(AppArmorBug):
            AbiRule('foo', False, False, deny=True)

    def test_ifexists_true(self):
        with self.assertRaises(AppArmorBug):
            AbiRule('foo', True, False)

class InvalidAbiTest(AATest):
    def _check_invalid_rawrule(self, rawrule, matches_regex = False):
        obj = None
        self.assertEqual(AbiRule.match(rawrule), matches_regex)
        with self.assertRaises(AppArmorException):
            obj = AbiRule.parse(rawrule)

        self.assertIsNone(obj, 'AbiRule handed back an object unexpectedly')

    def test_invalid_abi_missing_path(self):
        self._check_invalid_rawrule('abi ,', matches_regex=True)  # missing path

    def test_invalid_non_AbiRule(self):
        self._check_invalid_rawrule('dbus,')  # not a abi rule

#   def test_empty_data_1(self):
#       obj = AbiRule('foo', False, False)
#       obj.path = ''
#       # no path set
#       with self.assertRaises(AppArmorBug):
#           obj.get_clean(1)

class WriteAbiTestAATest(AATest):
    def _run_test(self, rawrule, expected):
        self.assertTrue(AbiRule.match(rawrule))
        obj = AbiRule.parse(rawrule)
        clean = obj.get_clean()
        raw = obj.get_raw()

        self.assertEqual(expected.strip(), clean, 'unexpected clean rule')
        self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')

    tests = [
        #  raw rule                                         clean rule
        ('     abi      <foo>   ,        ',                 'abi <foo>,'                     ),
        ('     abi       foo    ,        ',                 'abi "foo",'                     ),
        ('     abi      "foo"   ,        ',                 'abi "foo",'                     ),
        ('     abi       /foo   ,         ',                'abi "/foo",'                    ),
        ('     abi      "/foo"  ,         ',                'abi "/foo",'                    ),

        ('     abi      <foo>, # bar     ',                 'abi <foo>, # bar'               ),
        ('     abi       foo , # bar     ',                 'abi "foo", # bar'               ),
        ('     abi      "foo", # bar     ',                 'abi "foo", # bar'               ),
        ('     abi       /foo,  # bar     ',                'abi "/foo", # bar'              ),
        ('     abi      "/foo", # bar     ',                'abi "/foo", # bar'              ),
    ]

    def test_write_manually(self):
        obj = AbiRule('abs/foo', False, True, comment=' # cmt')

        expected = '    abi <abs/foo>, # cmt'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')


class AbiCoveredTest(AATest):
    def _run_test(self, param, expected):
        obj = AbiRule.parse(self.rule)
        check_obj = AbiRule.parse(param)

        self.assertTrue(AbiRule.match(param))

        self.assertEqual(obj.is_equal(check_obj), expected[0], 'Mismatch in is_equal, expected %s' % expected[0])
        self.assertEqual(obj.is_equal(check_obj, True), expected[1], 'Mismatch in is_equal/strict, expected %s' % expected[1])

        self.assertEqual(obj.is_covered(check_obj), expected[2], 'Mismatch in is_covered, expected %s' % expected[2])
        self.assertEqual(obj.is_covered(check_obj, True, True), expected[3], 'Mismatch in is_covered/exact, expected %s' % expected[3])

class AbiCoveredTest_01(AbiCoveredTest):
    rule = 'abi <foo>,'

    tests = [
        #   rule                             equal     strict equal    covered     covered exact
        ('abi <foo>,'                    , [ True    , True          , True      , True      ]),
        ('abi "foo",'                    , [ False   , False         , False     , False     ]),
        ('abi <foobar>,'                 , [ False   , False         , False     , False     ]),
        ('abi "foo",'                    , [ False   , False         , False     , False     ]),
    ]

class AbiCoveredTest_02(AbiCoveredTest):
    rule = 'abi "foo",'

    tests = [
        #   rule                            equal     strict equal    covered     covered exact
        ('abi <foo>,'                   , [ False   , False         , False     , False     ]),
        ('abi "foo",'                   , [ True    , True          , True      , True      ]),
        ('abi "foobar",'                , [ False   , False         , False     , False     ]),
        ('abi foo,'                     , [ True    , False         , True      , True      ]),
    ]

#class AbiCoveredTest_Invalid(AATest):
#   def test_borked_obj_is_covered_1(self):
#       obj = AbiRule.parse('abi <foo>')

#       testobj = AbiRule('foo', True, True)
#       testobj.path = ''

#       with self.assertRaises(AppArmorBug):
#           obj.is_covered(testobj)

#   def test_borked_obj_is_covered_2(self):
#       obj = AbiRule.parse('abi send set=quit peer=/foo,')

#       testobj = AbiRule('send', 'quit', '/foo')
#       testobj.abi = ''

#       with self.assertRaises(AppArmorBug):
#           obj.is_covered(testobj)

#   def test_borked_obj_is_covered_3(self):
#       obj = AbiRule.parse('abi send set=quit peer=/foo,')

#       testobj = AbiRule('send', 'quit', '/foo')
#       testobj.peer = ''

#       with self.assertRaises(AppArmorBug):
#           obj.is_covered(testobj)

#   def test_invalid_is_covered(self):
#       obj = AbiRule.parse('abi send,')

#       testobj = BaseRule()  # different type

#       with self.assertRaises(AppArmorBug):
#           obj.is_covered(testobj)

#   def test_invalid_is_equal(self):
#       obj = AbiRule.parse('abi send,')

#       testobj = BaseRule()  # different type

#       with self.assertRaises(AppArmorBug):
#           obj.is_equal(testobj)

class AbiLogprofHeaderTest(AATest):
    tests = [
        ('abi <abi/3.0>,',              [_('Abi'), 'abi <abi/3.0>,',        ]),
        ('abi "/foo/bar",',             [_('Abi'), 'abi "/foo/bar",',       ]),
    ]

    def _run_test(self, params, expected):
        obj = AbiRule.parse(params)
        self.assertEqual(obj.logprof_header(), expected)

## --- tests for AbiRuleset --- #

class AbiRulesTest(AATest):
    def test_empty_ruleset(self):
        ruleset = AbiRuleset()
        ruleset_2 = AbiRuleset()
        self.assertEqual([], ruleset.get_raw(2))
        self.assertEqual([], ruleset.get_clean(2))
        self.assertEqual([], ruleset_2.get_raw(2))
        self.assertEqual([], ruleset_2.get_clean(2))
        self.assertEqual([], ruleset_2.get_clean_unsorted(2))

    def test_ruleset_1(self):
        ruleset = AbiRuleset()
        rules = [
            ' abi  <foo>  ,',
            ' abi   "/bar", ',
        ]

        expected_raw = [
            'abi  <foo>  ,',
            'abi   "/bar",',
            '',
        ]

        expected_clean = [
            'abi "/bar",',
            'abi <foo>,',
            '',
        ]

        expected_clean_unsorted = [
            'abi <foo>,',
            'abi "/bar",',
            '',
        ]

        for rule in rules:
            ruleset.add(AbiRule.parse(rule))

        self.assertEqual(expected_raw, ruleset.get_raw())
        self.assertEqual(expected_clean, ruleset.get_clean())
        self.assertEqual(expected_clean_unsorted, ruleset.get_clean_unsorted())

class AbiGlobTestAATest(AATest):
    def setUp(self):
        self.maxDiff = None
        self.ruleset = AbiRuleset()

#   def test_glob(self):
#       with self.assertRaises(NotImplementedError):
#           # get_glob_ext is not available for include rules
#           self.ruleset.get_glob('include send set=int,')

    def test_glob_ext(self):
        with self.assertRaises(NotImplementedError):
            # get_glob_ext is not available for include rules
            self.ruleset.get_glob_ext('include send set=int,')

#class AbiDeleteTestAATest(AATest):
#    pass

setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
