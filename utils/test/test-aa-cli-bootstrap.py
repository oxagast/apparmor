#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2019 Otto Kekäläinen <otto@kekalainen.net>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest
from common_test import AATest, setup_all_loops, setup_aa

# Imports for test code
import io
import os
import sys

# Imports for AppArmor
import atexit
import apparmor.aa as aa
import apparmor.ui as aaui
from apparmor.common import DebugLogger
from apparmor.fail import enable_aa_exception_handler
from apparmor.translations import init_translation


class AACliBootstrapTest(AATest):
    '''
    Generic test of the core AppArmor Python libraries that all command
    line tools rely on.
    '''
    def AASetup(self):
        # Redirect sys.stdout to a buffer
        sys.stdout = io.StringIO()

        global _, debug_logger

        enable_aa_exception_handler()
        _ = init_translation()
        atexit.register(aa.on_exit)
        debug_logger = DebugLogger('Test AA')
        debug_logger.debug('Starting test')

    def AATeardown(self):
        debug_logger.debug('Ended test')

    def test_loadincludes(self):
        self.assertEqual(aa.loadincludes(), None)

    def test_i18n(self):
        self.assertEqual('Test string - do not translate', _('Test string - do not translate'))

    def test_aa_conf(self):
        confdir = os.getenv('__AA_CONFDIR')
        if confdir:
            self.assertEqual(aa.conf.CONF_DIR, confdir)
        else:
            self.assertEqual(aa.conf.CONF_DIR, '/etc/apparmor')

    def test_aa_ui_info(self):
        aaui.UI_Info('Test string')
        self.assertEqual(sys.stdout.getvalue(), 'Test string\n')

    def test_aa_ui_info_json(self):
        aaui.set_json_mode()
        sys.stdout.getvalue()
        aaui.UI_Info('Test string')
        self.assertEqual(sys.stdout.getvalue(), '{"dialog": "apparmor-json-version","data": "2.12"}\n{"dialog": "info","data": "Test string"}\n')
        aaui.set_text_mode()


setup_aa(aa)  # Wrapper for aa.init_aa()
setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
