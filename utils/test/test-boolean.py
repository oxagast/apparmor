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

from apparmor.rule.boolean import BooleanRule, BooleanRuleset
from apparmor.rule import BaseRule
from apparmor.common import AppArmorException, AppArmorBug
from apparmor.translations import init_translation
_ = init_translation()

exp = namedtuple('exp', ['comment',
        'varname', 'value'])

# --- tests for single BooleanRule --- #

class BooleanTest(AATest):
    def _compare_obj(self, obj, expected):
        # boolean variables don't support the allow, audit or deny keyword
        self.assertEqual(False, obj.allow_keyword)
        self.assertEqual(False, obj.audit)
        self.assertEqual(False, obj.deny)

        self.assertEqual(expected.varname, obj.varname)
        self.assertEqual(expected.value, obj.value)
        self.assertEqual(expected.comment, obj.comment)

class BooleanTestParse(BooleanTest):
    tests = [
        # rawrule                                            comment        varname    value
        ('$foo=true',                                 exp('',               '$foo',    'true'    )),
        ('$foo = false',                              exp('',               '$foo',    'false'   )),
        ('$foo=TrUe',                                 exp('',               '$foo',    'true'    )),
        ('$foo = FaLsE',                              exp('',               '$foo',    'false'   )),
        ('  $foo =   true   ',                        exp('',               '$foo',    'true'    )),
        ('  $foo =   true        # comment',          exp(' # comment',     '$foo',    'true'    )),
     ]

    def _run_test(self, rawrule, expected):
        self.assertTrue(BooleanRule.match(rawrule))
        obj = BooleanRule.parse(rawrule)
        self.assertEqual(rawrule.strip(), obj.raw_rule)
        self._compare_obj(obj, expected)

class BooleanTestParseInvalid(BooleanTest):
    tests = [
        # rawrule                                   matches regex   exception
        ('$foo =',                                  (False,         AppArmorException)),
        ('$ foo =      # comment',                  (False,         AppArmorException)),
        ('${foo =      ',                           (False,         AppArmorException)),
        # XXX RE_PROFILE_BOOLEAN allows a trailing comma even if the parser disallows it
        # ('$foo = true,',                            (True,          AppArmorException)),  # trailing comma
        # ('$foo = false   ,  ',                      (True,          AppArmorException)),  # trailing comma
        # ('$foo = true,   # comment',                (True,          AppArmorException)),  # trailing comma
    ]

    def _run_test(self, rawrule, expected):
        self.assertEqual(BooleanRule.match(rawrule), expected[0])
        with self.assertRaises(expected[1]):
            BooleanRule.parse(rawrule)

class BooleanFromInit(BooleanTest):
#   tests = [
#       # BooleanRule object                                        comment     varname     value
#       (BooleanRule('$foo',    True,                           exp('',         '$foo',     True              ))),
#       (BooleanRule('$foo',    False,                          exp('',         '$foo',     False             ))),
#       (BooleanRule('$foo',    True,       comment='# cmt'),   exp('# cmt',    '$foo',     True              ))),
#       (BooleanRule('$foo',    False,      comment='# cmt'),   exp('# cmt',    '$foo',     False             ))),
#   ]

    def _run_test(self, obj, expected):
        self._compare_obj(obj, expected)


class InvalidBooleanInit(AATest):
    tests = [
        # init params                     expected exception
        ([None,     True            ],      AppArmorBug),  # varname not a str
        (['',       True            ],      AppArmorException),  # empty varname
        (['foo',    True            ],      AppArmorException),  # varname not starting with '$'
        (['foo',    True            ],      AppArmorException),  # varname not starting with '$'

        (['$foo',   None            ],      AppArmorBug),  # value not a string
        (['$foo',   ''              ],      AppArmorException),  # empty value
        (['$foo',   'maybe'         ],      AppArmorException),  # invalid value
    ]

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            BooleanRule(params[0], params[1])

    def test_missing_params_1(self):
        with self.assertRaises(TypeError):
            BooleanRule()

    def test_missing_params_2(self):
        with self.assertRaises(TypeError):
            BooleanRule('$foo')

    def test_invalid_audit(self):
        with self.assertRaises(AppArmorBug):
            BooleanRule('$foo', 'true', audit=True)

    def test_invalid_deny(self):
        with self.assertRaises(AppArmorBug):
            BooleanRule('$foo', 'true', deny=True)


class InvalidBooleanTest(AATest):
    def _check_invalid_rawrule(self, rawrule, matches_regex=False):
        obj = None
        self.assertEqual(BooleanRule.match(rawrule), matches_regex)
        with self.assertRaises(AppArmorException):
            obj = BooleanRule.parse(rawrule)

        self.assertIsNone(obj, 'BooleanRule handed back an object unexpectedly')

    def test_invalid_missing_value(self):
        self._check_invalid_rawrule('$foo =  ', matches_regex=False)  # missing value

    def test_invalid_net_non_BooleanRule(self):
        self._check_invalid_rawrule('dbus,')  # not a boolean rule


class WriteBooleanTestAATest(AATest):
    tests = [
        #  raw rule                                                      clean rule
        ('  $foo  =  true   ',                                          '$foo = true'),
        ('  $foo  =  true   # comment',                                 '$foo = true'),
        ('  $foo   =    false   ',                                      '$foo = false'),
        ('  $foo   =    false      # comment',                          '$foo = false'),
    ]

    def _run_test(self, rawrule, expected):
        self.assertTrue(BooleanRule.match(rawrule))
        obj = BooleanRule.parse(rawrule)
        clean = obj.get_clean()
        raw = obj.get_raw()

        self.assertEqual(expected.strip(), clean, 'unexpected clean rule')
        self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')

    def test_write_manually_1(self):
        obj = BooleanRule('$foo', 'true')

        expected = '    $foo = true'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')

    def test_write_manually_2(self):
        obj = BooleanRule('$foo', 'false')

        expected = '    $foo = false'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')


class BooleanCoveredTest(AATest):
    def _run_test(self, param, expected):
        obj = BooleanRule.parse(self.rule)
        check_obj = BooleanRule.parse(param)

        self.assertTrue(BooleanRule.match(param))

        self.assertEqual(obj.is_equal(check_obj), expected[0], 'Mismatch in is_equal, expected %s' % expected[0])
        self.assertEqual(obj.is_equal(check_obj, True), expected[1], 'Mismatch in is_equal/strict, expected %s' % expected[1])

        self.assertEqual(obj.is_covered(check_obj), expected[2], 'Mismatch in is_covered, expected %s' % expected[2])
        self.assertEqual(obj.is_covered(check_obj, True, True), expected[3], 'Mismatch in is_covered/exact, expected %s' % expected[3])

class BooleanCoveredTest_01(BooleanCoveredTest):
    rule = '$foo = true'

    tests = [
        #   rule                                        equal     strict equal    covered     covered exact
        ('           $foo = true'                   , [ True    , True          , True      , True      ]),
        ('           $foo = TRUE'                   , [ True    , False         , True      , True      ]),  # upper vs. lower case
        ('           $foo = true   # comment'       , [ True    , False         , True      , True      ]),
        ('           $foo = false'                  , [ False   , False         , False     , False     ]),
        ('           $foo = false     # cmt'        , [ False   , False         , False     , False     ]),
        ('           $bar = true'                   , [ False   , False         , False     , False     ]),  # different variable name
     ]

class BooleanCoveredTest_02(BooleanCoveredTest):
    rule = '$foo = false'

    tests = [
        #   rule                                        equal     strict equal    covered     covered exact
        ('           $foo = false'                  , [ True    , True          , True      , True      ]),
        ('           $foo = false  # comment'       , [ True    , False         , True      , True      ]),
        ('           $foo = true'                   , [ False   , False         , False     , False     ]),
        ('           $foo = true      # cmt'        , [ False   , False         , False     , False     ]),
        ('           $bar = false'                  , [ False   , False         , False     , False     ]),  # different variable name
     ]

class BooleanCoveredTest_Invalid(AATest):
    def test_borked_obj_is_covered_2(self):
        obj = BooleanRule.parse('$foo = true')

        testobj = BooleanRule('$foo', 'true')
        testobj.value = ''

        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_invalid_is_covered_3(self):
        obj = BooleanRule.parse('$foo = true')

        testobj = BaseRule()  # different type

        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_invalid_is_equal(self):
        obj = BooleanRule.parse('$foo = true')

        testobj = BaseRule()  # different type

        with self.assertRaises(AppArmorBug):
            obj.is_equal(testobj)

class BooleanLogprofHeaderTest(AATest):
    tests = [
        ('$foo = true',                             [_('Boolean Variable'), '$foo = true'       ]),
    ]

    def _run_test(self, params, expected):
        obj = BooleanRule.parse(params)
        self.assertEqual(obj.logprof_header(), expected)

# --- tests for BooleanRuleset --- #

class BooleanRulesTest(AATest):
    def test_empty_ruleset(self):
        ruleset = BooleanRuleset()
        ruleset_2 = BooleanRuleset()
        self.assertEqual([], ruleset.get_raw(2))
        self.assertEqual([], ruleset.get_clean(2))
        self.assertEqual([], ruleset_2.get_raw(2))
        self.assertEqual([], ruleset_2.get_clean(2))

    def test_ruleset_1(self):
        ruleset = BooleanRuleset()
        rules = [
            '$foo = true',
            '$baz= false',
        ]

        expected_raw = [
            '$foo = true',
            '$baz= false',
            '',
        ]

        expected_clean = [
            '$baz = false',
            '$foo = true',
            '',
        ]

        expected_clean_unsorted = [
            '$foo = true',
            '$baz = false',
            '',
        ]

        for rule in rules:
            ruleset.add(BooleanRule.parse(rule))

        self.assertEqual(expected_raw, ruleset.get_raw())
        self.assertEqual(expected_clean, ruleset.get_clean())
        self.assertEqual(expected_clean_unsorted, ruleset.get_clean_unsorted())

    def test_ruleset_overwrite(self):
        ruleset = BooleanRuleset()

        ruleset.add(BooleanRule.parse('$foo = true'))
        with self.assertRaises(AppArmorException):
            ruleset.add(BooleanRule.parse('$foo = false'))  # attempt to redefine @{foo}

class BooleanGlobTestAATest(AATest):
    def setUp(self):
        self.ruleset = BooleanRuleset()

#   def test_glob_1(self):
#       with self.assertRaises(NotImplementedError):
#           self.ruleset.get_glob('$foo = true')

    def test_glob_ext(self):
        with self.assertRaises(NotImplementedError):
            # get_glob_ext is not available for boolean rules
            self.ruleset.get_glob_ext('$foo = true')

class BooleanDeleteTestAATest(AATest):
    pass

setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
