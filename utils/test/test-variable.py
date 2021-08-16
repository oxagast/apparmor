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

from apparmor.rule.variable import VariableRule, VariableRuleset, separate_vars
from apparmor.rule import BaseRule
from apparmor.common import AppArmorException, AppArmorBug
from apparmor.translations import init_translation
_ = init_translation()

exp = namedtuple('exp', ['comment',
        'varname', 'mode', 'values'])

# --- tests for single VariableRule --- #

class VariableTest(AATest):
    def _compare_obj(self, obj, expected):
        # variables don't support the allow, audit or deny keyword
        self.assertEqual(False, obj.allow_keyword)
        self.assertEqual(False, obj.audit)
        self.assertEqual(False, obj.deny)

        self.assertEqual(expected.varname, obj.varname)
        self.assertEqual(expected.mode, obj.mode)
        self.assertEqual(expected.values, obj.values)
        self.assertEqual(expected.comment, obj.comment)

class AaTest_separate_vars(AATest):
    tests = [
        (''                             , set()                      ),
        ('       '                      , set()                      ),
        ('  foo bar'                    , {'foo', 'bar'             }),
        ('foo "  '                      , AppArmorException          ),
        (' " foo '                      , AppArmorException          ), # half-quoted
        ('  foo bar   '                 , {'foo', 'bar'             }),
        ('  foo bar   # comment'        , {'foo', 'bar', '#', 'comment'}), # XXX should comments be stripped?
        ('foo'                          , {'foo'                    }),
        ('"foo" "bar baz"'              , {'foo', 'bar baz'         }),
        ('foo "bar baz" xy'             , {'foo', 'bar baz', 'xy'   }),
        ('foo "bar baz '                , AppArmorException          ), # half-quoted
        ('  " foo" bar'                 , {' foo', 'bar'            }),
        ('  " foo" bar x'               , {' foo', 'bar', 'x'       }),
        ('""'                           , {''                       }), # empty value
        ('"" foo'                       , {'', 'foo'                }), # empty value + 'foo'
        ('"" foo "bar"'                 , {'', 'foo', 'bar'         }), # empty value + 'foo' + 'bar' (bar has superfluous quotes)
        ('"bar"'                        , {'bar'                    }), # 'bar' with superfluous quotes
    ]

    def _run_test(self, params, expected):
        if expected == AppArmorException:
            with self.assertRaises(expected):
                separate_vars(params)
        else:
            result = separate_vars(params)
            self.assertEqual(result, expected)

class VariableTestParse(VariableTest):
    tests = [
        # rawrule                                            comment        varname    mode     values
        ('@{foo}=/bar',                                 exp('',             '@{foo}',  '=',     {'/bar'}         )),
        ('@{foo}+=/bar',                                exp('',             '@{foo}',  '+=',    {'/bar'}         )),
        ('  @{foo} =   /bar   ',                        exp('',             '@{foo}',  '=',     {'/bar'}         )),
        ('  @{foo}   +=    /bar',                       exp('',             '@{foo}',  '+=',    {'/bar'}         )),
        ('  @{foo} =   /bar        # comment',          exp(' # comment',   '@{foo}',  '=',     {'/bar'}         )),
        ('  @{foo}   +=    /bar   # comment',           exp(' # comment',   '@{foo}',  '+=',    {'/bar'}         )),
        ('@{foo}=/bar /baz',                            exp('',             '@{foo}',  '=',     {'/bar', '/baz'} )),
        ('@{foo} = "/bar,"   # comment',                exp(' # comment',   '@{foo}',  '=',     {'/bar,'}        )),  # value with trailing comma, needs to be quoted
     ]

    def _run_test(self, rawrule, expected):
        self.assertTrue(VariableRule.match(rawrule))
        obj = VariableRule.parse(rawrule)
        self.assertEqual(rawrule.strip(), obj.raw_rule)
        self._compare_obj(obj, expected)

class VariableTestParseInvalid(VariableTest):
    tests = [
        # rawrule                                   matches regex   exception
        ('@{foo} =',                                (False,         AppArmorException)),
        ('@ {foo} =      # comment',                (False,         AppArmorException)),
        ('@ {foo} =      ',                         (False,         AppArmorException)),
        ('@{foo} = /foo,',                          (True,          AppArmorException)),  # trailing comma
        ('@{foo} = /foo,   ',                       (True,          AppArmorException)),  # trailing comma
        ('@{foo} = /foo,   # comment',              (True,          AppArmorException)),  # trailing comma
        ('@{foo} = /foo, /bar',                     (True,          AppArmorException)),  # trailing comma in first value
        ('@{foo = /foo f',                          (True,          AppArmorException)),  # variable name broken, missing }
    ]

    def _run_test(self, rawrule, expected):
        self.assertEqual(VariableRule.match(rawrule), expected[0])
        with self.assertRaises(expected[1]):
            VariableRule.parse(rawrule)

class VariableFromInit(VariableTest):
    tests = [
        # VariableRule object                                           comment     varname     mode    values
        (VariableRule('@{foo}', '=',    {'/bar'}),                  exp('',         '@{foo}',   '=',    {'/bar'}            )),
        (VariableRule('@{foo}', '+=',   {'/bar'}),                  exp('',         '@{foo}',   '+=',   {'/bar'}            )),
        (VariableRule('@{foo}', '=',    {'/bar', '/baz'}),          exp('',         '@{foo}',   '=',    {'/bar', '/baz'}    )),
        (VariableRule('@{foo}', '+=',   {'/bar', '/baz'}),          exp('',         '@{foo}',   '+=',   {'/bar', '/baz'}    )),
        (VariableRule('@{foo}', '=',    {'/bar'}, comment='# cmt'), exp('# cmt',    '@{foo}',   '=',    {'/bar'}            )),
        (VariableRule('@{foo}', '+=',   {'/bar'}, comment='# cmt'), exp('# cmt',    '@{foo}',   '+=',   {'/bar'}            )),
    ]

    def _run_test(self, obj, expected):
        self._compare_obj(obj, expected)


class InvalidVariableInit(AATest):
    tests = [
        # init params                     expected exception
        ([None,     '=',    ['/bar']        ],      AppArmorBug),  # varname not a str
        (['',       '=',    ['/bar']        ],      AppArmorException),  # empty varname
        (['foo',    '=',    ['/bar']        ],      AppArmorException),  # varname not starting with '@{'
        (['foo',    '=',    ['/bar']        ],      AppArmorException),  # varname not starting with '@{'

        (['@{foo}', '',     ['/bar']        ],      AppArmorBug),  # mode not '=' or '+='
        (['@{foo}', '-=',   ['/bar']        ],      AppArmorBug),  # mode not '=' or '+='
        (['@{foo}', ' ',    ['/bar']        ],      AppArmorBug),  # mode not '=' or '+='
        (['@{foo}', None,   ['/bar']        ],      AppArmorBug),  # mode not '=' or '+='

        (['@{foo}', '=',    None            ],      AppArmorBug),  # values not a set
        (['@{foo}', '=',    set()           ],      AppArmorException),  # empty values
    ]

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            VariableRule(params[0], params[1], params[2])

    def test_missing_params_1(self):
        with self.assertRaises(TypeError):
            VariableRule()

    def test_missing_params_2(self):
        with self.assertRaises(TypeError):
            VariableRule('@{foo}')

    def test_missing_params_3(self):
        with self.assertRaises(TypeError):
            VariableRule('@{foo}', '=')

    def test_invalid_audit(self):
        with self.assertRaises(AppArmorBug):
            VariableRule('@{foo}', '=', '/bar', audit=True)

    def test_invalid_deny(self):
        with self.assertRaises(AppArmorBug):
            VariableRule('@{foo}', '=', '/bar', deny=True)


class InvalidVariableTest(AATest):
    def _check_invalid_rawrule(self, rawrule, matches_regex=False):
        obj = None
        self.assertEqual(VariableRule.match(rawrule), matches_regex)
        with self.assertRaises(AppArmorException):
            obj = VariableRule.parse(rawrule)

        self.assertIsNone(obj, 'VariableRule handed back an object unexpectedly')

    def test_invalid_missing_values(self):
        self._check_invalid_rawrule('@{foo} =  ', matches_regex=True)  # missing values

    def test_invalid_net_non_VariableRule(self):
        self._check_invalid_rawrule('dbus,')  # not a variable rule


class WriteVariableTestAATest(AATest):
    tests = [
        #  raw rule                                                      clean rule
        ('  @{foo}  =  /bar   ',                                        '@{foo} = /bar'),
        ('  @{foo}  =  /bar   # comment',                               '@{foo} = /bar'),
        ('  @{foo}  =  /bar  ""',                                       '@{foo} = "" /bar'),
        ('  @{foo}  +=  /bar   ',                                       '@{foo} += /bar'),
        ('  @{foo}  +=  /bar   # comment',                              '@{foo} += /bar'),
        ('  @{foo}  +=  /bar       /baz',                               '@{foo} += /bar /baz'),
        ('  @{foo}  +=  /bar       /baz',                               '@{foo} += /bar /baz'),
        ('  @{foo}  +=  /bar      @{baz}',                              '@{foo} += /bar @{baz}'),
        ('  @{foo}  +=  /bar      @{baz}',                              '@{foo} += /bar @{baz}'),
    ]

    def _run_test(self, rawrule, expected):
        self.assertTrue(VariableRule.match(rawrule))
        obj = VariableRule.parse(rawrule)
        clean = obj.get_clean()
        raw = obj.get_raw()

        self.assertEqual(expected.strip(), clean, 'unexpected clean rule')
        self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')

    def test_write_manually_1(self):
        obj = VariableRule('@{foo}', '=', {'/bar'})

        expected = '    @{foo} = /bar'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')

    def test_write_manually_2(self):
        obj = VariableRule('@{foo}', '=', {'/bar', ''})

        expected = '    @{foo} = "" /bar'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')


class VariableCoveredTest(AATest):
    def _run_test(self, param, expected):
        obj = VariableRule.parse(self.rule)
        check_obj = VariableRule.parse(param)

        self.assertTrue(VariableRule.match(param))

        self.assertEqual(obj.is_equal(check_obj), expected[0], 'Mismatch in is_equal, expected %s' % expected[0])
        self.assertEqual(obj.is_equal(check_obj, True), expected[1], 'Mismatch in is_equal/strict, expected %s' % expected[1])

        self.assertEqual(obj.is_covered(check_obj), expected[2], 'Mismatch in is_covered, expected %s' % expected[2])
        self.assertEqual(obj.is_covered(check_obj, True, True), expected[3], 'Mismatch in is_covered/exact, expected %s' % expected[3])

class VariableCoveredTest_01(VariableCoveredTest):
    rule = '@{foo} = /bar'

    tests = [
        #   rule                                        equal     strict equal    covered     covered exact
        ('           @{foo} = /bar'                 , [ True    , True          , True      , True      ]),
        ('           @{foo} += /bar'                , [ False   , False         , False     , False     ]),
        ('           @{foo} = /bar   # comment'     , [ True    , False         , True      , True      ]),
        ('           @{foo} += /bar  # comment'     , [ False   , False         , False     , False     ]),
        ('           @{foo} = /baz /bar'            , [ False   , False         , False     , False     ]),
        ('           @{foo} += /baz /bar'           , [ False   , False         , False     , False     ]),
        ('           @{foo} = /baz /bar # cmt'      , [ False   , False         , False     , False     ]),
        ('           @{foo} += /baz /bar # cmt'     , [ False   , False         , False     , False     ]),
        ('           @{bar} = /bar'                 , [ False   , False         , False     , False     ]),  # different variable name
     ]

class VariableCoveredTest_02(VariableCoveredTest):
    rule = '@{foo} = /bar /baz'

    tests = [
        #   rule                                       equal     strict equal    covered     covered exact
        ('           @{foo} = /bar /baz'            , [ True    , True          , True      , True      ]),
        ('           @{foo} += /bar /baz'           , [ False   , False         , False     , False     ]),
        ('           @{foo} = /bar /baz # cmt'      , [ True    , False         , True      , True      ]),
        ('           @{foo} += /bar /baz # cmt'     , [ False   , False         , False     , False     ]),
        # changed order of values
        ('           @{foo} = /baz /bar'            , [ True    , False         , True      , True      ]),
        ('           @{foo} += /baz /bar'           , [ False   , False         , False     , False     ]),
        ('           @{foo} = /baz /bar # cmt'      , [ True    , False         , True      , True      ]),
        ('           @{foo} += /baz /bar # cmt'     , [ False   , False         , False     , False     ]),
        # only one value
        ('           @{foo} = /bar'                 , [ False   , False         , True      , True      ]),
        ('           @{foo} += /bar'                , [ False   , False         , False     , False     ]),
        ('           @{foo} = /bar   # comment'     , [ False   , False         , True      , True      ]),
        ('           @{foo} += /bar  # comment'     , [ False   , False         , False     , False     ]),
        ('           @{bar} = /bar'                 , [ False   , False         , False     , False     ]),  # different variable name
        ]

class VariableCoveredTest_Invalid(AATest):
#   def test_borked_obj_is_covered_1(self):
#       obj = VariableRule.parse('@{foo} = /bar')

#       testobj = VariableRule('@{foo}', '=', '/bar')
#       testobj.mode = ''

#       with self.assertRaises(AppArmorBug):
#           obj.is_covered(testobj)

    def test_borked_obj_is_covered_2(self):
        obj = VariableRule.parse('@{foo} = /bar')

        testobj = VariableRule('@{foo}', '=', {'/bar'})
        testobj.values = ''

        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_invalid_is_covered_3(self):
        obj = VariableRule.parse('@{foo} = /bar')

        testobj = BaseRule()  # different type

        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_invalid_is_equal(self):
        obj = VariableRule.parse('@{foo} = /bar')

        testobj = BaseRule()  # different type

        with self.assertRaises(AppArmorBug):
            obj.is_equal(testobj)

class VariableLogprofHeaderTest(AATest):
    tests = [
        ('@{foo} = /bar',                           [_('Variable'), '@{foo} = /bar'     ]),
    ]

    def _run_test(self, params, expected):
        obj = VariableRule.parse(params)
        self.assertEqual(obj.logprof_header(), expected)

# --- tests for VariableRuleset --- #

class VariableRulesTest(AATest):
    def test_empty_ruleset(self):
        ruleset = VariableRuleset()
        ruleset_2 = VariableRuleset()
        self.assertEqual([], ruleset.get_raw(2))
        self.assertEqual([], ruleset.get_clean(2))
        self.assertEqual([], ruleset_2.get_raw(2))
        self.assertEqual([], ruleset_2.get_clean(2))
        self.assertEqual({'=': {}, '+=': {}}, ruleset_2.get_merged_variables())

    def test_ruleset_1(self):
        ruleset = VariableRuleset()
        rules = [
            '@{foo} = /bar',
            '@{baz}= /asdf',
            '@{foo}    +=   /whatever',
            '@{foo}    +=   /morestuff',
        ]

        expected_raw = [
            '@{foo} = /bar',
            '@{baz}= /asdf',
            '@{foo}    +=   /whatever',
            '@{foo}    +=   /morestuff',
            '',
        ]

        expected_clean = [
            '@{baz} = /asdf',
            '@{foo} += /morestuff',
            '@{foo} += /whatever',
            '@{foo} = /bar',
            '',
        ]

        expected_clean_unsorted = [
            '@{foo} = /bar',
            '@{baz} = /asdf',
            '@{foo} += /whatever',
            '@{foo} += /morestuff',
            '',
        ]

        expected_merged = {
            '=': {
                '@{foo}': {'/bar'},
                '@{baz}': {'/asdf'},
            },
            '+=': {
                '@{foo}': {'/whatever', '/morestuff'},
            }
        }

        for rule in rules:
            ruleset.add(VariableRule.parse(rule))

        self.assertEqual(expected_raw, ruleset.get_raw())
        self.assertEqual(expected_clean, ruleset.get_clean())
        self.assertEqual(expected_clean_unsorted, ruleset.get_clean_unsorted())
        self.assertEqual(expected_merged, ruleset.get_merged_variables())

    def test_ruleset_overwrite(self):
        ruleset = VariableRuleset()

        ruleset.add(VariableRule.parse('@{foo} = /bar'))
        with self.assertRaises(AppArmorException):
            ruleset.add(VariableRule.parse('@{foo} = /asdf'))  # attempt to redefine @{foo}
        self.assertEqual({'=': {'@{foo}': {'/bar'} }, '+=': {}}, ruleset.get_merged_variables())

class VariableGlobTestAATest(AATest):
    def setUp(self):
        self.ruleset = VariableRuleset()

#   def test_glob_1(self):
#       with self.assertRaises(NotImplementedError):
#           self.ruleset.get_glob('@{foo} = /bar')

    def test_glob_ext(self):
        with self.assertRaises(NotImplementedError):
            # get_glob_ext is not available for change_profile rules
            self.ruleset.get_glob_ext('@{foo} = /bar')

class VariableDeleteTestAATest(AATest):
    pass

setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
