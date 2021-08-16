#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2018 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest
from common_test import AATest, setup_aa, setup_all_loops, write_file

import apparmor.aa
import os
import shutil

from apparmor.common import AppArmorBug, AppArmorException
from apparmor.profile_list import ProfileList
from apparmor.profile_storage import ProfileStorage
from apparmor.rule.abi import AbiRule
from apparmor.rule.alias import AliasRule
from apparmor.rule.boolean import BooleanRule
from apparmor.rule.include import IncludeRule
from apparmor.rule.variable import VariableRule

class TestAdd_profile(AATest):
    def AASetup(self):
        self.pl = ProfileList()
        self.dummy_profile = ProfileStorage('TEST DUMMY', 'AATest_no_file', 'TEST')

    def testEmpty(self):
        self.assertEqual(self.pl.profile_names, {})
        self.assertEqual(self.pl.attachments, {})
        self.assertEqual('%s' % self.pl, "\n".join(['', '<ProfileList>', '', '</ProfileList>', '']))

    def testAdd_profile_1(self):
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo', self.dummy_profile)
        self.assertEqual(self.pl.profile_names, {'foo': '/etc/apparmor.d/bin.foo'})
        self.assertEqual(self.pl.attachments, {'/bin/foo': '/etc/apparmor.d/bin.foo'})
        self.assertEqual(self.pl.profiles_in_file('/etc/apparmor.d/bin.foo'), ['foo'])
        self.assertEqual('%s' % self.pl, '\n<ProfileList>\n/etc/apparmor.d/bin.foo\n</ProfileList>\n')

    def testAdd_profile_2(self):
        self.pl.add_profile('/etc/apparmor.d/bin.foo', None, '/bin/foo', self.dummy_profile)
        self.assertEqual(self.pl.profile_names, {})
        self.assertEqual(self.pl.attachments, {'/bin/foo': '/etc/apparmor.d/bin.foo'})
        self.assertEqual(self.pl.profiles_in_file('/etc/apparmor.d/bin.foo'), ['/bin/foo'])
        self.assertEqual('%s' % self.pl, '\n<ProfileList>\n/etc/apparmor.d/bin.foo\n</ProfileList>\n')

    def testAdd_profile_3(self):
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', None, self.dummy_profile)
        self.assertEqual(self.pl.profile_names, {'foo': '/etc/apparmor.d/bin.foo'})
        self.assertEqual(self.pl.attachments, {})
        self.assertEqual(self.pl.profiles_in_file('/etc/apparmor.d/bin.foo'), ['foo'])
        self.assertEqual('%s' % self.pl, '\n<ProfileList>\n/etc/apparmor.d/bin.foo\n</ProfileList>\n')

    def testAdd_profileError_1(self):
        with self.assertRaises(AppArmorBug):
            self.pl.add_profile('', 'foo', '/bin/foo', self.dummy_profile)  # no filename

    def testAdd_profileError_2(self):
        with self.assertRaises(AppArmorBug):
            self.pl.add_profile('/etc/apparmor.d/bin.foo', None, None, self.dummy_profile)  # neither attachment or profile name

    def testAdd_profileError_list_nonexisting_file(self):
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', None, self.dummy_profile)
        with self.assertRaises(AppArmorBug):
            self.pl.profiles_in_file('/etc/apparmor.d/not.found')  # different filename

    def testAdd_profileError_twice_1(self):
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo', self.dummy_profile)
        with self.assertRaises(AppArmorException):
            self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo', self.dummy_profile)

    def testAdd_profileError_twice_2(self):
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo', self.dummy_profile)
        with self.assertRaises(AppArmorException):
            self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', None, self.dummy_profile)

    def testAdd_profileError_twice_3(self):
        self.pl.add_profile('/etc/apparmor.d/bin.foo', None, '/bin/foo', self.dummy_profile)
        with self.assertRaises(AppArmorException):
            self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo', self.dummy_profile)

    def testAdd_profileError_twice_4(self):
        self.pl.add_profile('/etc/apparmor.d/bin.foo', None, '/bin/foo', self.dummy_profile)
        with self.assertRaises(AppArmorException):
            self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo', self.dummy_profile)

    def testAdd_profileError_twice_5(self):
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', None, self.dummy_profile)
        with self.assertRaises(AppArmorException):
            self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo', self.dummy_profile)

    def testAdd_profileError_wrong_prof_type(self):
        with self.assertRaises(AppArmorBug):
            self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo', 'wrong_type')

class TestFilename_from_profile_name(AATest):
    tests = [
        ('foo',         '/etc/apparmor.d/bin.foo'),
        ('/bin/foo',    None),
        ('bar',         None),
        ('/usr{,{/lib,/lib32,/lib64}/wine}/bin/wine{,-preloader,server}{,-staging-*,-vanilla-*}',   '/etc/apparmor.d/usr.bin.wine'),
        ('/usr/lib/wine/bin/wine-preloader-staging-foo',                                            None),  # no AARE matching for profile names
    ]

    def AASetup(self):
        self.pl = ProfileList()
        self.dummy_profile = ProfileStorage('TEST DUMMY', 'AATest_no_file', 'TEST')
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo', self.dummy_profile)
        self.pl.add_profile('/etc/apparmor.d/usr.bin.wine', '/usr{,{/lib,/lib32,/lib64}/wine}/bin/wine{,-preloader,server}{,-staging-*,-vanilla-*}', '/usr{,{/lib,/lib32,/lib64}/wine}/bin/wine{,-preloader,server}{,-staging-*,-vanilla-*}', self.dummy_profile)

    def _run_test(self, params, expected):
        self.assertEqual(self.pl.filename_from_profile_name(params), expected)

class TestFilename_from_attachment(AATest):
    tests = [
        ('/bin/foo',    '/etc/apparmor.d/bin.foo'),
        ('/bin/baz',    '/etc/apparmor.d/bin.baz'),
        ('/bin/foobar', '/etc/apparmor.d/bin.foobar'),
        ('@{foo}',      None),  # XXX variables not supported yet (and @{foo} isn't defined in this test)
        ('/bin/404',    None),
        ('/usr{,{/lib,/lib32,/lib64}/wine}/bin/wine{,-preloader,server}{,-staging-*,-vanilla-*}',   '/etc/apparmor.d/usr.bin.wine'),  # XXX should this really match, or should attachment matching only use AARE?
        ('/usr/lib/wine/bin/wine-preloader-staging-foo',                                            '/etc/apparmor.d/usr.bin.wine'),  # AARE match
    ]

    def AASetup(self):
        self.pl = ProfileList()
        self.dummy_profile = ProfileStorage('TEST DUMMY', 'AATest_no_file', 'TEST')
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo', self.dummy_profile)
        self.pl.add_profile('/etc/apparmor.d/bin.baz', 'baz', '/bin/ba*', self.dummy_profile)
        self.pl.add_profile('/etc/apparmor.d/bin.foobar', 'foobar', '/bin/foo{bar,baz}', self.dummy_profile)
        self.pl.add_profile('/etc/apparmor.d/usr.bin.wine', '/usr{,{/lib,/lib32,/lib64}/wine}/bin/wine{,-preloader,server}{,-staging-*,-vanilla-*}', '/usr{,{/lib,/lib32,/lib64}/wine}/bin/wine{,-preloader,server}{,-staging-*,-vanilla-*}', self.dummy_profile)

    def _run_test(self, params, expected):
        self.assertEqual(self.pl.filename_from_attachment(params), expected)

    def test_non_path_attachment(self):
        with self.assertRaises(AppArmorBug):
            self.pl.filename_from_attachment('foo')

class TestAdd_inc_ie(AATest):
    def AASetup(self):
        self.pl = ProfileList()

    def testAdd_inc_ie_1(self):
        self.pl.add_inc_ie('/etc/apparmor.d/bin.foo', IncludeRule('tunables/global', False, True))
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['include <tunables/global>', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['include <tunables/global>', ''])

    def testAdd_inc_ie_2(self):
        self.pl.add_inc_ie('/etc/apparmor.d/bin.foo', IncludeRule('tunables/global', False, True))
        self.pl.add_inc_ie('/etc/apparmor.d/bin.foo', IncludeRule('tunables/dovecot', False, True))
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['include <tunables/global>', 'include <tunables/dovecot>', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['include <tunables/global>', 'include <tunables/dovecot>', ''])

    def testAdd_inc_ie_error_1(self):
        with self.assertRaises(AppArmorBug):
            self.pl.add_inc_ie('/etc/apparmor.d/bin.foo', 'tunables/global')  # str insteadd of IncludeRule
        self.assertEqual(list(self.pl.files.keys()), [])

    def test_dedup_inc_ie_1(self):
        self.pl.add_inc_ie('/etc/apparmor.d/bin.foo', IncludeRule.parse('include <tunables/global>'))
        self.pl.add_inc_ie('/etc/apparmor.d/bin.foo', IncludeRule.parse('#include if exists <tunables/global>  # comment'))
        self.pl.add_inc_ie('/etc/apparmor.d/bin.foo', IncludeRule.parse('   #include         <tunables/global>    '))
        deleted = self.pl.delete_preamble_duplicates('/etc/apparmor.d/bin.foo')
        self.assertEqual(deleted, 2)
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['include <tunables/global>', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['include <tunables/global>', ''])

    def test_dedup_error_1(self):
        with self.assertRaises(AppArmorBug):
            self.pl.delete_preamble_duplicates('/file/not/found')
        self.assertEqual(list(self.pl.files.keys()), [])

class TestAdd_abi(AATest):
    def AASetup(self):
        self.pl = ProfileList()

    def testAdd_abi_1(self):
        self.pl.add_abi('/etc/apparmor.d/bin.foo', AbiRule('abi/4.19', False, True))
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['abi <abi/4.19>,', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['abi <abi/4.19>,', ''])

    def testAdd_abi_2(self):
        self.pl.add_abi('/etc/apparmor.d/bin.foo', AbiRule('abi/4.19', False, True))
        self.pl.add_abi('/etc/apparmor.d/bin.foo', AbiRule('foo', False, False))
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['abi <abi/4.19>,', 'abi "foo",', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['abi <abi/4.19>,', 'abi "foo",', ''])

    def testAdd_abi_error_1(self):
        with self.assertRaises(AppArmorBug):
            self.pl.add_abi('/etc/apparmor.d/bin.foo', 'abi/4.19')  # str insteadd of AbiRule
        self.assertEqual(list(self.pl.files.keys()), [])

    def test_dedup_abi_1(self):
        self.pl.add_abi('/etc/apparmor.d/bin.foo', AbiRule.parse('abi <abi/4.19>,'))
        self.pl.add_abi('/etc/apparmor.d/bin.foo', AbiRule.parse('   abi     <abi/4.19>  ,  # comment'))
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        deleted = self.pl.delete_preamble_duplicates('/etc/apparmor.d/bin.foo')
        self.assertEqual(deleted, 1)
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['abi <abi/4.19>,', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['abi <abi/4.19>,', ''])

class TestAdd_alias(AATest):
    def AASetup(self):
        self.pl = ProfileList()

    def testAdd_alias_1(self):
        self.pl.add_alias('/etc/apparmor.d/bin.foo', AliasRule('/foo', '/bar'))
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['alias /foo -> /bar,', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['alias /foo -> /bar,', ''])

    def testAdd_alias_2(self):
        self.pl.add_alias('/etc/apparmor.d/bin.foo', AliasRule('/foo', '/bar'))
        self.pl.add_alias('/etc/apparmor.d/bin.foo', AliasRule('/xyz', '/zyx'))
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['alias /foo -> /bar,', 'alias /xyz -> /zyx,', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['alias /foo -> /bar,', 'alias /xyz -> /zyx,', ''])

    def testAdd_alias_two_targets(self):
        self.pl.add_alias('/etc/apparmor.d/bin.foo', AliasRule('/foo', '/bar'))
        self.pl.add_alias('/etc/apparmor.d/bin.foo', AliasRule('/foo', '/another_target'))
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['alias /foo -> /bar,', 'alias /foo -> /another_target,', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['alias /foo -> /bar,', 'alias /foo -> /another_target,', ''])

    def testAdd_alias_error_1(self):
        with self.assertRaises(AppArmorBug):
            self.pl.add_alias('/etc/apparmor.d/bin.foo', AliasRule(None, '/foo'))  # alias None insteadd of str
        self.assertEqual(list(self.pl.files.keys()), [])

    def testAdd_alias_error_2(self):
        with self.assertRaises(AppArmorBug):
            self.pl.add_alias('/etc/apparmor.d/bin.foo', AliasRule('/foo', None))  # target None insteadd of str
        self.assertEqual(list(self.pl.files.keys()), [])

    def testAdd_alias_error_3(self):
        with self.assertRaises(AppArmorBug):
            self.pl.add_alias('/etc/apparmor.d/bin.foo', 'alias /foo -> /bar,')  # str insteadd of AliasRule
        self.assertEqual(list(self.pl.files.keys()), [])

    def test_dedup_alias_1(self):
        self.pl.add_alias('/etc/apparmor.d/bin.foo', AliasRule('/foo', '/bar'))
        self.pl.add_alias('/etc/apparmor.d/bin.foo', AliasRule('/foo', '/another_target'))
        self.pl.add_alias('/etc/apparmor.d/bin.foo', AliasRule('/foo', '/bar'))  # duplicate
        deleted = self.pl.delete_preamble_duplicates('/etc/apparmor.d/bin.foo')
        self.assertEqual(deleted, 1)
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['alias /foo -> /bar,', 'alias /foo -> /another_target,', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['alias /foo -> /bar,', 'alias /foo -> /another_target,', ''])

class TestAdd_variable(AATest):
    def AASetup(self):
        self.pl = ProfileList()

    def testAdd_variable_1(self):
        self.pl.add_variable('/etc/apparmor.d/bin.foo', VariableRule('@{foo}', '=', {'/foo'}))
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['@{foo} = /foo', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['@{foo} = /foo', ''])

    def testAdd_variable_2(self):
        self.pl.add_variable('/etc/apparmor.d/bin.foo', VariableRule('@{foo}', '=', {'/foo'}))
        self.pl.add_variable('/etc/apparmor.d/bin.foo', VariableRule('@{bar}', '=', {'/bar'}))
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['@{foo} = /foo', '@{bar} = /bar', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['@{foo} = /foo', '@{bar} = /bar', ''])

    def testAdd_variable_error_1(self):
        with self.assertRaises(AppArmorBug):
            self.pl.add_variable('/etc/apparmor.d/bin.foo', '@{foo}')  # str insteadd of IncludeRule
        self.assertEqual(list(self.pl.files.keys()), [])

    def test_dedup_variable_1(self):
        self.pl.add_variable('/etc/apparmor.d/bin.foo', VariableRule.parse('@{foo} = /foo'))
        self.pl.add_variable('/etc/apparmor.d/bin.foo', VariableRule.parse('@{foo} += /bar  # comment'))
        self.pl.add_variable('/etc/apparmor.d/bin.foo', VariableRule.parse('@{foo}    += /bar /baz'))
        deleted = self.pl.delete_preamble_duplicates('/etc/apparmor.d/bin.foo')
        self.assertEqual(deleted, 1)
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['@{foo} = /foo', '@{foo} += /bar /baz', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['@{foo} = /foo', '@{foo}    += /bar /baz', ''])

    def test_dedup_error_1(self):
        with self.assertRaises(AppArmorBug):
            self.pl.delete_preamble_duplicates('/file/not/found')
        self.assertEqual(list(self.pl.files.keys()), [])

class TestAdd_boolean(AATest):
    def AASetup(self):
        self.pl = ProfileList()

    def testAdd_variable_1(self):
        self.pl.add_boolean('/etc/apparmor.d/bin.foo', BooleanRule('$foo', 'true'))
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['$foo = true', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['$foo = true', ''])

    def testAdd_variable_2(self):
        self.pl.add_boolean('/etc/apparmor.d/bin.foo', BooleanRule('$foo', 'true'))
        self.pl.add_boolean('/etc/apparmor.d/bin.foo', BooleanRule('$bar', 'false'))
        self.assertEqual(list(self.pl.files.keys()), ['/etc/apparmor.d/bin.foo'])
        self.assertEqual(self.pl.get_clean('/etc/apparmor.d/bin.foo'), ['$foo = true', '$bar = false', ''])
        self.assertEqual(self.pl.get_raw('/etc/apparmor.d/bin.foo'), ['$foo = true', '$bar = false', ''])

    def testAdd_variable_error_1(self):
        with self.assertRaises(AppArmorBug):
            self.pl.add_boolean('/etc/apparmor.d/bin.foo', '$foo')  # str insteadd of IncludeRule
        self.assertEqual(list(self.pl.files.keys()), [])

class TestGet(AATest):
    def AASetup(self):
        self.pl = ProfileList()

    def testGet_clean_error(self):
        with self.assertRaises(AppArmorBug):
            self.pl.get_clean('/etc/apparmor.d/not.found')

    def testGet_raw_error(self):
        with self.assertRaises(AppArmorBug):
            self.pl.get_raw('/etc/apparmor.d/not.found')

class AaTest_get_all_merged_variables(AATest):
    tests = []

    def AASetup(self):
        self.createTmpdir()

        # copy the local profiles to the test directory
        self.profile_dir = '%s/profiles' % self.tmpdir
        apparmor.aa.profile_dir = self.profile_dir
        shutil.copytree('../../profiles/apparmor.d/', self.profile_dir, symlinks=True)

    def _load_profiles(self):
        apparmor.aa.reset_aa()

        # load the profiles and abstractions
        apparmor.aa.profile_dir = self.profile_dir
        apparmor.aa.loadincludes()
        apparmor.aa.read_profiles()

    def test_unchanged(self):
        self._load_profiles()
        prof_filename = os.path.join(self.profile_dir, 'usr.sbin.dnsmasq')
        vars = apparmor.aa.active_profiles.get_all_merged_variables(os.path.join(self.profile_dir, 'usr.sbin.dnsmasq'), apparmor.aa.include_list_recursive(apparmor.aa.active_profiles.files[prof_filename], True))
        self.assertEqual(vars['@{TFTP_DIR}'], {'/var/tftp', '/srv/tftp', '/srv/tftpboot'})
        self.assertEqual(vars['@{HOME}'], {'@{HOMEDIRS}/*/', '/root/'})

    def test_extended_home(self):
        write_file(self.profile_dir, 'tunables/home.d/extend_home', '@{HOME} += /my/castle/')
        self._load_profiles()
        prof_filename = os.path.join(self.profile_dir, 'usr.sbin.dnsmasq')
        vars = apparmor.aa.active_profiles.get_all_merged_variables(os.path.join(self.profile_dir, 'usr.sbin.dnsmasq'), apparmor.aa.include_list_recursive(apparmor.aa.active_profiles.files[prof_filename], True))
        self.assertEqual(vars['@{TFTP_DIR}'], {'/var/tftp', '/srv/tftp', '/srv/tftpboot'})
        self.assertEqual(vars['@{HOME}'], {'@{HOMEDIRS}/*/', '/root/', '/my/castle/'})

    def test_extended_home_2(self):
        write_file(self.profile_dir, 'tunables/home.d/extend_home', '@{HOME} += /my/castle/')
        write_file(self.profile_dir, 'tunables/home.d/moving_around', '@{HOME} += /on/the/road/')
        self._load_profiles()
        prof_filename = os.path.join(self.profile_dir, 'usr.sbin.dnsmasq')
        vars = apparmor.aa.active_profiles.get_all_merged_variables(os.path.join(self.profile_dir, 'usr.sbin.dnsmasq'), apparmor.aa.include_list_recursive(apparmor.aa.active_profiles.files[prof_filename], True))
        self.assertEqual(vars['@{TFTP_DIR}'], {'/var/tftp', '/srv/tftp', '/srv/tftpboot'})
        self.assertEqual(vars['@{HOME}'], {'@{HOMEDIRS}/*/', '/root/', '/my/castle/', '/on/the/road/'})

    def test_extend_home_in_mainfile(self):
        write_file(self.profile_dir, 'tunables/home.d/extend_home', '@{HOME} += /my/castle/')
        write_file(self.profile_dir, 'dummy_profile', 'include <tunables/global>\n@{HOME} += /in/the/profile/')
        self._load_profiles()
        prof_filename = os.path.join(self.profile_dir, 'dummy_profile')
        vars = apparmor.aa.active_profiles.get_all_merged_variables(os.path.join(self.profile_dir, 'dummy_profile'), apparmor.aa.include_list_recursive(apparmor.aa.active_profiles.files[prof_filename], True))
        self.assertEqual(vars.get('@{TFTP_DIR}', None), None)
        self.assertEqual(vars['@{HOME}'], {'@{HOMEDIRS}/*/', '/root/', '/my/castle/', '/in/the/profile/'})

    def test_redefine_home(self):
        write_file(self.profile_dir, 'tunables/home.d/overwrite_home', '@{HOME} = /my/castle/')  # note: =, not +=
        self._load_profiles()
        prof_filename = os.path.join(self.profile_dir, 'usr.sbin.dnsmasq')
        with self.assertRaises(AppArmorException):
            apparmor.aa.active_profiles.get_all_merged_variables(os.path.join(self.profile_dir, 'usr.sbin.dnsmasq'), apparmor.aa.include_list_recursive(apparmor.aa.active_profiles.files[prof_filename], True))

    def test_add_to_nonexisting(self):
        write_file(self.profile_dir, 'tunables/home.d/no_such_var', '@{NO_SUCH_HOME} += /my/castle/')  # add to non-existing variable
        self._load_profiles()
        prof_filename = os.path.join(self.profile_dir, 'usr.sbin.dnsmasq')
        with self.assertRaises(AppArmorException):
            apparmor.aa.active_profiles.get_all_merged_variables(os.path.join(self.profile_dir, 'usr.sbin.dnsmasq'), apparmor.aa.include_list_recursive(apparmor.aa.active_profiles.files[prof_filename], True))

    def test_vars_from_nonexisting_profile(self):
        with self.assertRaises(AppArmorBug):
            apparmor.aa.active_profiles.get_all_merged_variables(os.path.join(self.profile_dir, 'file.not.found'), list())

class TestGet_profile_and_childs(AATest):
    def AASetup(self):
        self.pl = ProfileList()
        self.dummy_profile = ProfileStorage('TEST DUMMY', 'AATest_no_file', 'TEST')

    def testGet_profile_and_childs1(self):
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'bafoo',     '/bin/bafoo',       self.dummy_profile)
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo',       '/bin/foo',         self.dummy_profile)
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foobar',    '/bin/foobar',      self.dummy_profile)
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo//bar',  '/bin/foo//bar',    self.dummy_profile)
        self.pl.add_profile('/etc/apparmor.d/bin.foo', 'foo//xy',   '/bin/foo//xy',     self.dummy_profile)

        expected = ['foo', 'foo//bar', 'foo//xy']

        self.assertEqual(list(self.pl.get_profile_and_childs('foo')), expected)


setup_aa(apparmor.aa)
setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
