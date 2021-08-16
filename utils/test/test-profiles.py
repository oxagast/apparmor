#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2020 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest
from common_test import AATest, setup_all_loops, setup_aa
import apparmor.aa as aa

# If a profile can't be parsed by the tools, add it to skip_active_profiles or skip_extra_profiles.
# Add only the filename (without path), for example 'usr.bin.foo'.
# These skip lists are meant as a temporary solution, and should be empty on release.
skip_active_profiles = [
]

skip_extra_profiles = [
]

class TestFoo(AATest):
    # Make sure the python code can parse all profiles shipped with AppArmor.
    # If this fails, read_profiles() / read_inactive_profiles() will raise an exception.
    #
    # Checking for the number of read profiles is mostly done to ensure *something* is read
    # (to make sure an empty or non-existing directory won't make this test useless).

    def test_active_profiles(self):
        aa.read_profiles(skip_profiles=skip_active_profiles)

        self.assertGreaterEqual(len(aa.active_profiles.profile_names), 42)

    def test_extra_profiles(self):
        aa.read_inactive_profiles(skip_profiles=skip_extra_profiles)

        self.assertGreaterEqual(len(aa.extra_profiles.profile_names), 100)

setup_aa(aa)
setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
