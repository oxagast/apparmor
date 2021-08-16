#! /bin/bash
#	Copyright (C) 2015 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME aa_policy_cache
#=DESCRIPTION
# This test verifies that the aa_policy_cache API works as expected.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

# cacheloc is the top level directory of cache directories
cacheloc="$tmpdir/cache"

# cachedir will be a subdirectory of the $cacheloc and its name will be
# influenced by the features available in the currently running kernel
#
# the test helper will call into libapparmor to query the cacheloc path
cachedir=$("$test" cache-dir "$cacheloc")

policies=$(echo aa_policy_cache_test_{0001..1024})

create_cacheloc()
{
	mkdir -p "$cacheloc"
}

remove_cacheloc()
{
	if [ -n "$cacheloc" ]
	then
		rm -rf "$cacheloc"
	fi
}

create_empty_cachedir()
{
	$test new --max-caches 1 "$cacheloc" > /dev/null
}

create_cache_files()
{
	local cachefile

	mkdir -p "$cachedir"
	for policy in $policies
	do
		cachefile="${cachedir}/${policy}"

		echo "profile $policy { /f r, }" | ${subdomain} "${parser_config}" -qS > "$cachefile"
	done
}

install_bad_features_file()
{
	echo "file {\n}\n" > "${cachedir}/.features"
}

remove_features_file()
{
	if [ -n "$cachedir" ]
	then
		rm -f "${cachedir}/.features"
	fi
}

verify_policies_are_not_loaded()
{
	for policy in $policies
	do
		if grep -q "^policy " /sys/kernel/security/apparmor/profiles
		then
			fatalerror "Policy \"${policy}\" must not be loaded"
			return
		fi
	done
}

runchecktest_policies_are_loaded()
{
	for policy in $policies
	do
		if ! grep -q "^$policy (enforce)" /sys/kernel/security/apparmor/profiles
		then
			echo "Error: Policy \"${policy}\" was not loaded"
			testfailed
			return
		fi
	done
}

runchecktest_remove_policies()
{
	for policy in $policies
	do
		runchecktest "AA_POLICY_CACHE remove-policy ($policy)" pass remove-policy "$policy"
	done
}

# IMPORTANT: These tests build on themselves so the first failing test can
# cause many failures

runchecktest "AA_POLICY_CACHE new (no cacheloc)" fail new "$cacheloc"
create_cacheloc
runchecktest "AA_POLICY_CACHE new (no .features)" fail new "$cacheloc"
remove_cacheloc
runchecktest "AA_POLICY_CACHE new create (no cacheloc)" pass new --max-caches 1 "$cacheloc"
runchecktest "AA_POLICY_CACHE new create (existing cache)" pass new --max-caches 1 "$cacheloc"
runchecktest "AA_POLICY_CACHE new (existing cache)" pass new "$cacheloc"

install_bad_features_file
runchecktest "AA_POLICY_CACHE new (bad .features)" fail new "$cacheloc"
runchecktest "AA_POLICY_CACHE new create (bad .features)" pass new --max-caches 1 "$cacheloc"

# Make sure that no test policies are already loaded
verify_policies_are_not_loaded

remove_cacheloc
runchecktest "AA_POLICY_CACHE replace-all (no cacheloc)" fail replace-all "$cacheloc"
create_cacheloc
runchecktest "AA_POLICY_CACHE replace-all (no .features)" fail replace-all "$cacheloc"
create_empty_cachedir
runchecktest "AA_POLICY_CACHE replace-all (empty cachedir)" pass replace-all "$cacheloc"
create_cache_files
runchecktest "AA_POLICY_CACHE replace-all (full cache)" pass replace-all "$cacheloc"

# Test that the previous policy load was successful 
runchecktest_policies_are_loaded

runchecktest "AA_POLICY_CACHE remove-policy (DNE)" fail remove-policy "aa_policy_cache_test_DNE"
runchecktest_remove_policies

runchecktest "AA_POLICY_CACHE remove (full cache)" pass remove "$cacheloc"
create_empty_cachedir
remove_features_file
runchecktest "AA_POLICY_CACHE remove (no .features)" pass remove "$cacheloc"
create_empty_cachedir
runchecktest "AA_POLICY_CACHE remove (empty cache)" pass remove "$cacheloc"
remove_cacheloc
runchecktest "AA_POLICY_CACHE remove (DNE)" fail remove "$cacheloc"
