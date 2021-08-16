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

from apparmor.rule.alias import AliasRule, AliasRuleset
from apparmor.rule import BaseRule
from apparmor.common import AppArmorException, AppArmorBug
from apparmor.translations import init_translation
_ = init_translation()

exp = namedtuple('exp', ['comment',
        'orig_path', 'target'])

# --- tests for single AliasRule --- #

class AliasTest(AATest):
    def _compare_obj(self, obj, expected):
        # aliass don't support the allow, audit or deny keyword
        self.assertEqual(False, obj.allow_keyword)
        self.assertEqual(False, obj.audit)
        self.assertEqual(False, obj.deny)

        self.assertEqual(expected.orig_path, obj.orig_path)
        self.assertEqual(expected.target, obj.target)
        self.assertEqual(expected.comment, obj.comment)

class AliasTestParse(AliasTest):
    tests = [
        # rawrule                                            comment        orig_path       target
        ('alias /foo -> /bar,',                         exp('',             '/foo',         '/bar'      )),
        ('  alias   /foo    ->    /bar ,  # comment',   exp(' # comment',   '/foo',         '/bar'      )),
        ('alias "/foo 2" -> "/bar 2"  ,',               exp('',             '/foo 2',       '/bar 2'    )),
     ]

    def _run_test(self, rawrule, expected):
        self.assertTrue(AliasRule.match(rawrule))
        obj = AliasRule.parse(rawrule)
        self.assertEqual(rawrule.strip(), obj.raw_rule)
        self._compare_obj(obj, expected)

class AliasTestParseInvalid(AliasTest):
    tests = [
        # rawrule                                   matches regex   exception
        ('alias  ,'                               , (False,         AppArmorException)),
        ('alias   /foo  ,'                        , (False,         AppArmorException)),
        ('alias   /foo   ->   ,'                  , (True,          AppArmorException)),
        ('alias   ->   /bar  ,'                   , (True,          AppArmorException)),
        ('/foo  ->   bar ,'                       , (False,         AppArmorException)),
    ]

    def _run_test(self, rawrule, expected):
        self.assertEqual(AliasRule.match(rawrule), expected[0])
        with self.assertRaises(expected[1]):
            AliasRule.parse(rawrule)

class AliasFromInit(AliasTest):
    tests = [
        # AliasRule object                                  comment     orig_path   target
        (AliasRule('/foo',  '/bar'),                    exp('',         '/foo',     '/bar'  )),
        (AliasRule('/foo',  '/bar', comment='# cmt'),   exp('# cmt',    '/foo',     '/bar'  )),
    ]

    def _run_test(self, obj, expected):
        self._compare_obj(obj, expected)


class InvalidAliasInit(AATest):
    tests = [
        # init params                           expected exception
        ([None,         '/bar'          ],      AppArmorBug),  # orig_path not a str
        (['',           '/bar'          ],      AppArmorException),  # empty orig_path
        (['foo',        '/bar'          ],      AppArmorException),  # orig_path not starting with /

        (['/foo',       None            ],      AppArmorBug),  # target not a str
        (['/foo',       ''              ],      AppArmorException),  # empty target
        (['/foo',       'bar'           ],      AppArmorException),  # target not starting with /
    ]

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            AliasRule(params[0], params[1])

    def test_missing_params_1(self):
        with self.assertRaises(TypeError):
            AliasRule()

    def test_missing_params_2(self):
        with self.assertRaises(TypeError):
            AliasRule('/foo')

    def test_invalid_audit(self):
        with self.assertRaises(AppArmorBug):
            AliasRule('/foo', '/bar', audit=True)

    def test_invalid_deny(self):
        with self.assertRaises(AppArmorBug):
            AliasRule('/foo', '/bar', deny=True)


class InvalidAliasTest(AATest):
    def _check_invalid_rawrule(self, rawrule, matches_regex=False):
        obj = None
        self.assertEqual(AliasRule.match(rawrule), matches_regex)
        with self.assertRaises(AppArmorException):
            obj = AliasRule.parse(rawrule)

        self.assertIsNone(obj, 'AliasRule handed back an object unexpectedly')

    def test_invalid_missing_orig_path(self):
        self._check_invalid_rawrule('alias    ->  /bar ,  ', matches_regex=True)  # missing orig_path

    def test_invalid_missing_target(self):
        self._check_invalid_rawrule('alias /foo  ->   ,  ', matches_regex=True)  # missing target

    def test_invalid_net_non_AliasRule(self):
        self._check_invalid_rawrule('dbus,')  # not a alias rule


class WriteAliasTestAATest(AATest):
    tests = [
        #  raw rule                                                     clean rule
        ('  alias  /foo  ->  /bar,  ',                                  'alias /foo -> /bar,'),
        ('  alias  /foo  ->  /bar,  # comment',                         'alias /foo -> /bar,'),
        ('  alias  "/foo"  ->  "/bar",  ',                              'alias /foo -> /bar,'),
        ('  alias  "/foo 2"  ->  "/bar 2",  ',                          'alias "/foo 2" -> "/bar 2",'),
    ]

    def _run_test(self, rawrule, expected):
        self.assertTrue(AliasRule.match(rawrule))
        obj = AliasRule.parse(rawrule)
        clean = obj.get_clean()
        raw = obj.get_raw()

        self.assertEqual(expected.strip(), clean, 'unexpected clean rule')
        self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')

    def test_write_manually_1(self):
        obj = AliasRule('/foo', '/bar')

        expected = '    alias /foo -> /bar,'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')

    def test_write_manually_2(self):
        obj = AliasRule('/foo 2', '/bar 2')

        expected = '    alias "/foo 2" -> "/bar 2",'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')


class AliasCoveredTest(AATest):
    def _run_test(self, param, expected):
        obj = AliasRule.parse(self.rule)
        check_obj = AliasRule.parse(param)

        self.assertTrue(AliasRule.match(param))

        self.assertEqual(obj.is_equal(check_obj), expected[0], 'Mismatch in is_equal, expected %s' % expected[0])
        self.assertEqual(obj.is_equal(check_obj, True), expected[1], 'Mismatch in is_equal/strict, expected %s' % expected[1])

        self.assertEqual(obj.is_covered(check_obj), expected[2], 'Mismatch in is_covered, expected %s' % expected[2])
        self.assertEqual(obj.is_covered(check_obj, True, True), expected[3], 'Mismatch in is_covered/exact, expected %s' % expected[3])

class AliasCoveredTest_01(AliasCoveredTest):
    rule = 'alias /foo -> /bar,'

    tests = [
        #   rule                                            equal     strict equal    covered     covered exact
        ('           alias /foo -> /bar,'               , [ True    , True          , True      , True      ]),
        ('           alias   /foo   ->    /bar  ,  '    , [ True    , False         , True      , True      ]),
        ('           alias /foo -> /bar,   # comment'   , [ True    , False         , True      , True      ]),
        ('           alias /foo ->  /bar,  # comment'   , [ True    , False         , True      , True      ]),
        ('           alias /foo -> /asdf,'              , [ False   , False         , False     , False     ]),
        ('           alias /whatever -> /bar,'          , [ False   , False         , False     , False     ]),
        ('           alias /whatever -> /asdf,'         , [ False   , False         , False     , False     ]),
     ]

class AliasCoveredTest_Invalid(AATest):
#   def test_borked_obj_is_covered_1(self):
#       obj = AliasRule.parse('alias /foo -> /bar,')

#       testobj = AliasRule('/foo', '/bar')

#       with self.assertRaises(AppArmorBug):
#           obj.is_covered(testobj)

#   def test_borked_obj_is_covered_2(self):
#       obj = AliasRule.parse('alias /foo -> /bar,')

#       testobj = AliasRule('/foo', '/bar')
#       testobj.target = ''

#       with self.assertRaises(AppArmorBug):
#           obj.is_covered(testobj)

    def test_invalid_is_covered_3(self):
        obj = AliasRule.parse('alias /foo -> /bar,')

        testobj = BaseRule()  # different type

        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_invalid_is_equal(self):
        obj = AliasRule.parse('alias /foo -> /bar,')

        testobj = BaseRule()  # different type

        with self.assertRaises(AppArmorBug):
            obj.is_equal(testobj)

class AliasLogprofHeaderTest(AATest):
    tests = [
        ('alias /foo -> /bar,',                         [_('Alias'), '/foo -> /bar'     ]),
    ]

    def _run_test(self, params, expected):
        obj = AliasRule.parse(params)
        self.assertEqual(obj.logprof_header(), expected)

# --- tests for AliasRuleset --- #

class AliasRulesTest(AATest):
    def test_empty_ruleset(self):
        ruleset = AliasRuleset()
        ruleset_2 = AliasRuleset()
        self.assertEqual([], ruleset.get_raw(2))
        self.assertEqual([], ruleset.get_clean(2))
        self.assertEqual([], ruleset_2.get_raw(2))
        self.assertEqual([], ruleset_2.get_clean(2))

    def test_ruleset_1(self):
        ruleset = AliasRuleset()
        rules = [
            'alias /foo -> /bar,',
            '  alias  /asdf   ->   /whatever  ,',
            'alias /asdf -> /somewhere,',
            'alias /foo -> /bar,',
        ]

        expected_raw = [
            'alias /foo -> /bar,',
            'alias  /asdf   ->   /whatever  ,',
            'alias /asdf -> /somewhere,',
            'alias /foo -> /bar,',
            '',
        ]

        expected_clean = [
            'alias /asdf -> /somewhere,',
            'alias /asdf -> /whatever,',
            'alias /foo -> /bar,',
            'alias /foo -> /bar,',
            '',
        ]

        expected_clean_unsorted = [
            'alias /foo -> /bar,',
            'alias /asdf -> /whatever,',
            'alias /asdf -> /somewhere,',
            'alias /foo -> /bar,',
            '',
        ]

        for rule in rules:
            ruleset.add(AliasRule.parse(rule))

        self.assertEqual(expected_raw, ruleset.get_raw())
        self.assertEqual(expected_clean, ruleset.get_clean())
        self.assertEqual(expected_clean_unsorted, ruleset.get_clean_unsorted())

class AliasGlobTestAATest(AATest):
    def setUp(self):
        self.ruleset = AliasRuleset()

#   def test_glob_1(self):
#       with self.assertRaises(NotImplementedError):
#           self.ruleset.get_glob('@{foo} = /bar')

    def test_glob_ext(self):
        with self.assertRaises(NotImplementedError):
            # get_glob_ext is not available for change_profile rules
            self.ruleset.get_glob_ext('@{foo} = /bar')

class AliasDeleteTestAATest(AATest):
    pass

setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
