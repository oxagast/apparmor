#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2011-2012 Canonical Ltd.
#    Copyright (C) 2019 Otto Kekäläinen
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import os
import signal
import subprocess
import tempfile
import time
import unittest

from common_test import AATest, setup_all_loops, setup_aa
import apparmor.aa as aa

# The location of the aa-notify utility can be overridden by setting
# the APPARMOR_NOTIFY environment variable; this is useful for running
# these tests in an installed environment
aanotify_bin = ["../aa-notify"]

# http://www.chiark.greenend.org.uk/ucgi/~cjwatson/blosxom/2009-07-02-python-sigpipe.html
# This is needed so that the subprocesses that produce endless output
# actually quit when the reader goes away.
def subprocess_setup():
    # Python installs a SIGPIPE handler by default. This is usually not what
    # non-Python subprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def cmd(command):
    '''Try to execute given command (array) and return its stdout, or return
    a textual error if it failed.'''

    try:
        sp = subprocess.Popen(
            command,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            preexec_fn=subprocess_setup
        )
    except OSError as e:
        return [127, str(e)]

    stdout, stderr = sp.communicate(input)

    # If there was some error output, show that instead of stdout to ensure
    # test fails and does not mask potentially major warnings and errors.
    if stderr:
        out = stderr
    else:
        out = stdout

    return [sp.returncode, out.decode('utf-8')]


class AANotifyTest(AATest):

    def AASetup(self):
        '''Create temporary log file with 30 enties of different age'''

        test_logfile_contents_999_days_old = \
'''Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834382] audit: type=1400 audit({epoch}:113): apparmor="ALLOWED" operation="exec" profile="libreoffice-soffice" name="/bin/uname" pid=4097 comm="sh" requested_mask="x" denied_mask="x" fsuid=1001 ouid=0 target="libreoffice-soffice//null-/bin/uname"
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834888] audit: type=1400 audit({epoch}:114): apparmor="ALLOWED" operation="file_inherit" profile="libreoffice-soffice//null-/bin/uname" name="/dev/null" pid=4097 comm="uname" requested_mask="w" denied_mask="w" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834890] audit: type=1400 audit({epoch}:115): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/bin/uname" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835136] audit: type=1400 audit({epoch}:116): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/ld-2.27.so" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835377] audit: type=1400 audit({epoch}:117): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/etc/ld.so.cache" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835405] audit: type=1400 audit({epoch}:118): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/libc-2.27.so" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835421] audit: type=1400 audit({epoch}:119): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/libc-2.27.so" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835696] audit: type=1400 audit({epoch}:120): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/usr/lib/locale/locale-archive" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.875891] audit: type=1400 audit({epoch}:121): apparmor="ALLOWED" operation="exec" profile="libreoffice-soffice" name="/usr/bin/file" pid=4111 comm="soffice.bin" requested_mask="x" denied_mask="x" fsuid=1001 ouid=0 target="libreoffice-soffice//null-/usr/bin/file"
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.880347] audit: type=1400 audit({epoch}:122): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/usr/bin/file" name="/usr/bin/file" pid=4111 comm="file" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
'''.format(epoch=round(time.time(), 3) - 60*60*24*999)

        test_logfile_contents_30_days_old = \
'''Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834382] audit: type=1400 audit({epoch}:113): apparmor="ALLOWED" operation="exec" profile="libreoffice-soffice" name="/bin/uname" pid=4097 comm="sh" requested_mask="x" denied_mask="x" fsuid=1001 ouid=0 target="libreoffice-soffice//null-/bin/uname"
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834888] audit: type=1400 audit({epoch}:114): apparmor="ALLOWED" operation="file_inherit" profile="libreoffice-soffice//null-/bin/uname" name="/dev/null" pid=4097 comm="uname" requested_mask="w" denied_mask="w" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834890] audit: type=1400 audit({epoch}:115): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/bin/uname" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835136] audit: type=1400 audit({epoch}:116): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/ld-2.27.so" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835377] audit: type=1400 audit({epoch}:117): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/etc/ld.so.cache" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835405] audit: type=1400 audit({epoch}:118): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/libc-2.27.so" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835421] audit: type=1400 audit({epoch}:119): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/libc-2.27.so" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835696] audit: type=1400 audit({epoch}:120): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/usr/lib/locale/locale-archive" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.875891] audit: type=1400 audit({epoch}:121): apparmor="ALLOWED" operation="exec" profile="libreoffice-soffice" name="/usr/bin/file" pid=4111 comm="soffice.bin" requested_mask="x" denied_mask="x" fsuid=1001 ouid=0 target="libreoffice-soffice//null-/usr/bin/file"
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.880347] audit: type=1400 audit({epoch}:122): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/usr/bin/file" name="/usr/bin/file" pid=4111 comm="file" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
'''.format(epoch=round(time.time(), 3) - 60*60*24*30)

        test_logfile_contents_unrelevant_entries = \
'''Feb  1 19:35:44 XPS-13-9370 kernel: [99848.048761] audit: type=1400 audit(1549042544.968:72): apparmor="STATUS" operation="profile_load" profile="unconfined" name="/snap/core/6350/usr/lib/snapd/snap-confine" pid=12871 comm="apparmor_parser"
Feb  2 00:40:09 XPS-13-9370 kernel: [103014.549071] audit: type=1400 audit(1549060809.600:89): apparmor="STATUS" operation="profile_load" profile="unconfined" name="docker-default" pid=17195 comm="apparmor_parser"
Feb  4 20:05:42 XPS-13-9370 kernel: [132557.202931] audit: type=1400 audit(1549303542.661:136): apparmor="STATUS" operation="profile_replace" info="same as current profile, skipping" profile="unconfined" name="snap.atom.apm" pid=11306 comm="apparmor_parser"
'''

        test_logfile_contents_0_seconds_old = \
'''Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834382] audit: type=1400 audit({epoch}:113): apparmor="ALLOWED" operation="exec" profile="libreoffice-soffice" name="/bin/uname" pid=4097 comm="sh" requested_mask="x" denied_mask="x" fsuid=1001 ouid=0 target="libreoffice-soffice//null-/bin/uname"
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834888] audit: type=1400 audit({epoch}:114): apparmor="ALLOWED" operation="file_inherit" profile="libreoffice-soffice//null-/bin/uname" name="/dev/null" pid=4097 comm="uname" requested_mask="w" denied_mask="w" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.834890] audit: type=1400 audit({epoch}:115): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/bin/uname" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835136] audit: type=1400 audit({epoch}:116): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/ld-2.27.so" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835377] audit: type=1400 audit({epoch}:117): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/etc/ld.so.cache" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835405] audit: type=1400 audit({epoch}:118): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/libc-2.27.so" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835421] audit: type=1400 audit({epoch}:119): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/bin/uname" name="/lib/x86_64-linux-gnu/libc-2.27.so" pid=4097 comm="uname" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.835696] audit: type=1400 audit({epoch}:120): apparmor="ALLOWED" operation="open" profile="libreoffice-soffice//null-/bin/uname" name="/usr/lib/locale/locale-archive" pid=4097 comm="uname" requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.875891] audit: type=1400 audit({epoch}:121): apparmor="ALLOWED" operation="exec" profile="libreoffice-soffice" name="/usr/bin/file" pid=4111 comm="soffice.bin" requested_mask="x" denied_mask="x" fsuid=1001 ouid=0 target="libreoffice-soffice//null-/usr/bin/file"
Feb  4 13:40:38 XPS-13-9370 kernel: [128552.880347] audit: type=1400 audit({epoch}:122): apparmor="ALLOWED" operation="file_mmap" profile="libreoffice-soffice//null-/usr/bin/file" name="/usr/bin/file" pid=4111 comm="file" requested_mask="rm" denied_mask="rm" fsuid=1001 ouid=0
'''.format(epoch=round(time.time(), 3))

        handle, self.test_logfile = tempfile.mkstemp(prefix='test-aa-notify-')
        os.close(handle)
        handle = open(self.test_logfile, "w+")
        handle.write(
            test_logfile_contents_999_days_old +
            test_logfile_contents_30_days_old +
            test_logfile_contents_unrelevant_entries +
            test_logfile_contents_0_seconds_old
        )
        handle.close()

    def AATeardown(self):
        '''Remove temporary log file after tests ended'''

        if self.test_logfile and os.path.exists(self.test_logfile):
            os.remove(self.test_logfile)

    # The Perl aa-notify script was written so, that it will checked for kern.log
    # before printing help when invoked without arguments (sic!).
    @unittest.skipUnless(os.path.isfile('/var/log/kern.log'), 'Requires kern.log on system')
    def test_no_arguments(self):
        '''Test using no arguments at all'''

        expected_return_code = 0
        expected_output_has = 'usage: aa-notify'

        return_code, output = cmd(aanotify_bin)
        result = 'Got return code %d, expected %d\n' % (return_code, expected_return_code)
        self.assertEqual(expected_return_code, return_code, result + output)
        result = 'Got output "%s", expected "%s"\n' % (output, expected_output_has)
        self.assertIn(expected_output_has, output, result + output)

    def test_help_contents(self):
        '''Test output of help text'''

        expected_return_code = 0
        expected_output_is = \
'''usage: aa-notify [-h] [-p] [--display DISPLAY] [-f FILE] [-l] [-s NUM] [-v]
                 [-u USER] [-w NUM] [--debug]

Display AppArmor notifications or messages for DENIED entries.

optional arguments:
  -h, --help            show this help message and exit
  -p, --poll            poll AppArmor logs and display notifications
  --display DISPLAY     set the DISPLAY environment variable (might be needed if
                        sudo resets $DISPLAY)
  -f FILE, --file FILE  search FILE for AppArmor messages
  -l, --since-last      display stats since last login
  -s NUM, --since-days NUM
                        show stats for last NUM days (can be used alone or with
                        -p)
  -v, --verbose         show messages with stats
  -u USER, --user USER  user to drop privileges to when not using sudo
  -w NUM, --wait NUM    wait NUM seconds before displaying notifications (with
                        -p)
  --debug               debug mode
'''

        return_code, output = cmd(aanotify_bin + ['--help'])
        result = 'Got return code %d, expected %d\n' % (return_code, expected_return_code)
        self.assertEqual(expected_return_code, return_code, result + output)
        result = 'Got output "%s", expected "%s"\n' % (output, expected_output_is)
        self.assertEqual(expected_output_is, output, result + output)

    def test_entries_since_100_days(self):
        '''Test showing log entries since 100 days'''

        expected_return_code = 0
        expected_output_has = 'AppArmor denials: 20 (since'

        return_code, output = cmd(aanotify_bin + ['-f', self.test_logfile, '-s', '100'])
        result = 'Got return code %d, expected %d\n' % (return_code, expected_return_code)
        self.assertEqual(expected_return_code, return_code, result + output)
        result = 'Got output "%s", expected "%s"\n' % (output, expected_output_has)
        self.assertIn(expected_output_has, output, result + output)

    @unittest.skipUnless(os.path.isfile('/var/log/wtmp'), 'Requires wtmp on system')
    def test_entries_since_login(self):
        '''Test showing log entries since last login'''

        expected_return_code = 0
        expected_output_has = 'AppArmor denials: 10 (since'

        return_code, output = cmd(aanotify_bin + ['-f', self.test_logfile, '-l'])
        if "ERROR: Could not find last login" in output:
            self.skipTest('Could not find last login')
        result = 'Got return code %d, expected %d\n' % (return_code, expected_return_code)
        self.assertEqual(expected_return_code, return_code, result + output)
        result = 'Got output "%s", expected "%s"\n' % (output, expected_output_has)
        self.assertIn(expected_output_has, output, result + output)

    @unittest.skipUnless(os.path.isfile('/var/log/wtmp'), 'Requires wtmp on system')
    def test_entries_since_login_verbose(self):
        '''Test showing log entries since last login in verbose mode'''

        expected_return_code = 0
        expected_output_has = \
'''Profile: libreoffice-soffice
Operation: exec
Name: /bin/uname
Denied: x
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: file_inherit
Name: /dev/null
Denied: w
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: file_mmap
Name: /bin/uname
Denied: rm
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: file_mmap
Name: /lib/x86_64-linux-gnu/ld-2.27.so
Denied: rm
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: open
Name: /etc/ld.so.cache
Denied: r
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: open
Name: /lib/x86_64-linux-gnu/libc-2.27.so
Denied: r
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: file_mmap
Name: /lib/x86_64-linux-gnu/libc-2.27.so
Denied: rm
Logfile: {logfile}

Profile: libreoffice-soffice//null-/bin/uname
Operation: open
Name: /usr/lib/locale/locale-archive
Denied: r
Logfile: {logfile}

Profile: libreoffice-soffice
Operation: exec
Name: /usr/bin/file
Denied: x
Logfile: {logfile}

Profile: libreoffice-soffice//null-/usr/bin/file
Operation: file_mmap
Name: /usr/bin/file
Denied: rm
Logfile: {logfile}

AppArmor denials: 10 (since'''.format(logfile=self.test_logfile)

        return_code, output = cmd(aanotify_bin + ['-f', self.test_logfile, '-l', '-v'])
        if "ERROR: Could not find last login" in output:
            self.skipTest('Could not find last login')
        result = 'Got return code %d, expected %d\n' % (return_code, expected_return_code)
        self.assertEqual(expected_return_code, return_code, result + output)
        result = 'Got output "%s", expected "%s"\n' % (output, expected_output_has)
        self.assertIn(expected_output_has, output, result + output)


setup_aa(aa)  # Wrapper for aa.init_aa()
setup_all_loops(__name__)
if __name__ == '__main__':
    if 'APPARMOR_NOTIFY' in os.environ:
        aanotify_bin = os.environ['APPARMOR_NOTIFY']

    if '__AA_CONFDIR' in os.environ:
        aanotify_bin = aanotify_bin + ['--configdir', os.getenv('__AA_CONFDIR')]

    unittest.main(verbosity=1)
