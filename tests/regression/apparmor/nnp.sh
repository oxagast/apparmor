#! /bin/bash
#	Copyright (C) 2019 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME nnp
#=DESCRIPTION
# Verifies AppArmor interactions with NO_NEW_PRIVS
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

settest transition

file=$tmpdir/file
okperm=rw

fileok="${file}:${okperm}"

getcon="/proc/*/attr/current:r"
setcon="/proc/*/attr/current:w"
setexec="/proc/*/attr/exec:w"
policy="/sys/kernel/security/apparmor/"

touch $file

# Verify file access by an unconfined process
runchecktest "NNP (unconfined - no NNP)" pass -f "$file"
runchecktest "NNP (unconfined - NNP)" pass -n -f "$file"

# Verify file access under simple confinement
genprofile "$fileok" "$getcon"
runchecktest "NNP (confined - no NNP)" pass -f "$file"
runchecktest "NNP (confined - NNP)" pass -n -f "$file"

# Verify that NNP allows ix transitions
genprofile image="$test" "$fileok" "$getcon"
runchecktest "NNP (ix - no NNP)" pass -- "$test" -f "$file"
runchecktest "NNP (ix - NNP)" pass -- "$test" -n -f "$file"

# Verify that NNP causes unconfined profile transition failures
# NNP-induced failures will use EPERM rather than EACCES
genprofile -I "$test":rux "$fileok"
runchecktest "NNP (ux - no NNP)" pass -- "$test" -f "$file"
runchecktest_errno EPERM "NNP (ux - NNP)" fail -n -- "$test" -f "$file"

# Verify that NNP causes discrete profile transition failures
genprofile "$bin/open":px -- image="$bin/open" "$fileok"
runchecktest "NNP (px - no NNP)" pass -- "$bin/open" "$file"
runchecktest_errno EPERM "NNP (px - NNP)" fail -n -- "$bin/open" "$file"

# Verify that NNP causes change onexec failures
genprofile "change_profile->":"$bin/open" "$setexec" -- image="$bin/open" "$fileok"
runchecktest "NNP (change onexec - no NNP)" pass -O "$bin/open" -- "$bin/open" "$file"
runchecktest_errno EPERM "NNP (change onexec - NNP)" fail -n -O "$bin/open" -- "$bin/open" "$file"

# Verify that NNP causes change profile failures
genprofile "change_profile->":"$bin/open" "$setcon" -- image="$bin/open"
runchecktest "NNP (change profile - no NNP)" pass -P "$bin/open"
runchecktest_errno EPERM "NNP (change profile - NNP)" fail -n -P "$bin/open"

if [ "$(kernel_features_istrue domain/stack)" != "true" ] ; then
    echo "	kernel does not support profile stacking - skipping stacking nnp tests ..."
else

    # Verify that NNP allows stack onexec of another profile
    genprofile "$fileok" "$setexec" "change_profile->:&${bin}/open" -- image="$bin/open" "$fileok"
    runchecktest "NNP (stack onexec - no NNP)" pass -o "$bin/open" -- "$bin/open" "$file"
    runchecktest "NNP (stack onexec - NNP)" pass -n -o "$bin/open" -- "$bin/open" "$file"

    # Verify that NNP allows stacking another profile
    genprofile "$fileok" "$setcon" "change_profile->:&$bin/open" -- image="$bin/open" "$fileok"
    runchecktest "NNP (stack profile - no NNP)" pass -p "$bin/open" -f "$file"
    runchecktest "NNP (stack profile - NNP)" pass -n -p "$bin/open" -f "$file"

    #Verify that NNP allow stacking unconfined along current profile
    #this allows verifying that a stack with unconfined still gets the
    #unconfined exception applied. It also tests that dropping unconfined
    #from the stack is allowed. ie.
    # transition//&unconfined -> transition//&open
    # and
    # transition//&unconfined -> transition//&open//&unconfined
    genprofile "$fileok" "$setcon" "change_profile->:&$bin/open" "change_profile->:&unconfined" -- image="$bin/open" "$fileok"
    runchecktest "NNP (stack profile&unconfined - no NNP)" pass -i "&unconfined" -p "$bin/open" -f "$file"
    runchecktest "NNP (stack profile&unconfined - NNP)" pass -n -i "&unconfined" -p "$bin/open" -f "$file"

    genprofile "$fileok" "$setcon" "change_profile->:$bin/transition" "change_profile->:$bin/open" "change_profile->:&unconfined" -- image="$bin/open" "$fileok"
    runchecktest "NNP (change profile&unconfined - no NNP)" pass -i "&unconfined" -P "$bin/transition//&$bin/open" -f "$file"
    runchecktest "NNP (change profile&unconfined - NNP)" pass -n -i "&unconfined" -P "$bin/transition//&$bin/open" -f "$file"


    #Verify that NNP allows stacking a new policy namespace
    #must use stdin with genprofile for namespaces
    genprofile --stdin <<EOF
$test {
    @{gen_bin $test}
    @{gen_def}
    ${file} ${okperm},
    /proc/*/attr/current w,
    change_profile-> &:nnp:unconfined,
}
:nnp:$bin/open {
    @{gen_bin $bin/open}
    @{gen_def}
    ${file} ${okperm},
}
EOF
    #genprofile is creating child namespace so mkdir not needed
    runchecktest "NNP (stack :nnp:unconfined - no NNP)" pass -p ":nnp:unconfined" -f "$file"
    runchecktest "NNP (stack :nnp:unconfined - NNP)" pass -n -p ":nnp:unconfined" -f "$file"

    runchecktest "NNP (stack :nnp:open - no NNP)" fail -p ":nnp:$bin/open" -f "$file"
    runchecktest "NNP (stack :nnp:open - NNP)" fail -n -p ":nnp:$bin/open" -f "$file"

    genprofile --stdin <<EOF
$test {
    @{gen_bin $test}
    @{gen_def}
    ${file} ${okperm},
    /proc/*/attr/current w,
    change_profile-> &:nnp:$bin/open,
}
:nnp:$bin/open {
    @{gen_bin $bin/open}
    @{gen_def}
    ${file} ${okperm},
}
EOF
     runchecktest "NNP (stack :nnp:open - no NNP)" pass -p ":nnp:$bin/open" -f "$file"
    runchecktest "NNP (stack :nnp:open - NNP)" pass -n -p ":nnp:$bin/open" -f "$file"
    # explicitly remove profile before cleaning up the namespace so
    # prologue.inc auto cleanup doesn't fail
    removeprofile
    echo -n  ":nnp:" > "$policy/.remove" || echo "   warning failed to remove namespace policy/namespaces/nnp"

fi
