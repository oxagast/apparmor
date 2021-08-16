#!/usr/bin/python3
# ------------------------------------------------------------------
#
#   Copyright (C) 2010-2011 Canonical Ltd.
#   Copyright (C) 2020 Christian Boltz
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of version 2 of the GNU General Public
#   License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

from testlib import write_file

prefix = "simple_tests/generated_x"
prefix_leading = "simple_tests/generated_perms_leading"
prefix_safe = "simple_tests/generated_perms_safe"

trans_types = ("p", "P", "c", "C", "u", "i")
modifiers = ("i", "u")
trans_modifiers = {
    "p": modifiers,
    "P": modifiers,
    "c": modifiers,
    "C": modifiers,
}

targets = ("", "target", "target2")
# null_target uses "_" instead of "" because "" gets skipped in some for loops. Replace with "" when actually using the value.
null_target = ("_")

named_trans = {
    "p": targets,
    "P": targets,
    "c": targets,
    "C": targets,
    "u": null_target,
    "i": null_target,
}

safe_map = {
    "p": "unsafe",
    "P": "safe",
    "c": "unsafe",
    "C": "safe",
    "u": "",
    "i": "",
}

invert_safe = {
    "safe": "unsafe",
    "unsafe": "safe",
    '': '',
}

# audit qualifier disabled for now it really shouldn't affect the conflict
# test but it may be worth checking every once in awhile
# qualifiers = ("", "owner", "audit", "audit owner")
qualifiers = ("", "owner")

count = 0

def gen_list():
    output = []
    for trans in trans_types:
        if trans in trans_modifiers:
            for mod in trans_modifiers[trans]:
                output.append("%s%sx" % (trans, mod))

        output.append("%sx" % trans)

    return output

def test_gen_list():
    ''' test if gen_list returns the expected output '''

    expected = "pix pux px Pix Pux Px cix cux cx Cix Cux Cx ux ix".split()
    actual = gen_list()

    if actual != expected:
        raise Exception("gen_list produced unexpected result, expected %s, got %s" % (expected, actual))

def build_rule(leading, qual, name, perm, target):
    rule = ''

    if leading:
        rule += "\t%s %s %s" % (qual, perm, name)
    else:
        rule += "\t%s %s %s" % (qual, name, perm)

    if target != "":
        rule += " -> %s" % target

    rule += ",\n"

    return rule

def gen_file (name, xres, leading1, qual1, rule1, perm1, target1, leading2, qual2, rule2, perm2, target2):
    global count
    count += 1

    content = ''
    content += "#\n"
    content += "#=DESCRIPTION %s\n" % name
    content += "#=EXRESULT %s\n" % xres
    content += "#\n"
    content += "/usr/bin/foo {\n"
    content += build_rule(leading1, qual1, rule1, perm1, target1)
    content += build_rule(leading2, qual2, rule2, perm2, target2)
    content += "}\n"

    write_file('', name, content)


# NOTE: currently we don't do px to cx, or cx to px conversion
#      so
# /foo {
#    /* px -> /foo//bar,
#    /* cx -> bar,
#
# will conflict
#
# NOTE: conflict tests don't tests leading permissions or using unsafe keywords
#      It is assumed that there are extra tests to verify 1 to 1 coorispondance
def gen_files(name, rule1, rule2, default):
    perms = gen_list()

    for i in perms:
        for t in named_trans[i[0]]:
            if t == '_':
                t = ''
            for q in qualifiers:
                for j in perms:
                    for u in named_trans[j[0]]:
                        if u == '_':
                            u = ''
                        for r in qualifiers:
                            file = prefix + '/' + name + '-' + q + i + t + '-' + r + j + u + '.sd'

                            # override failures when transitions are the same
                            xres = default
                            if (i == j and t == u):
                                xres = "PASS"

                            gen_file(file, xres, 0, q, rule1, i, t, 0, r, rule2, j, u)

def gen_conflicting_x():
    gen_files("conflict", "/bin/cat", "/bin/cat", "FAIL")

def gen_overlap_re_exact():
    gen_files("exact", "/bin/cat", "/bin/*", "PASS")

# we currently don't support this, once supported change to "PASS"
def gen_dominate_re_re():
    gen_files("dominate", "/bin/*", "/bin/**", "FAIL")

def gen_ambiguous_re_re():
    gen_files("ambiguous", "/bin/a*", "/bin/*b", "FAIL")


# test that rules that lead with permissions don't conflict with
# the same rule using trailing permissions.
def gen_leading_perms (name, rule1, rule2):
    perms = gen_list()

    for i in perms:
        for t in named_trans[i[0]]:
            if t == '_':
                t = ''
            for q in qualifiers:
                file = prefix_leading + '/' + name + '-' + q + i + t + ".sd"
                gen_file(file, "PASS", 0, q, rule1, i, t, 1, q, rule2, i, t)

# test for rules with leading safe or unsafe keywords.
# check they are equivalent to their counter part,
# or if $invert that they properly conflict with their counterpart
def gen_safe_perms(name, xres, invert, rule1, rule2):
    perms = gen_list()

    for i in perms:
        for t in named_trans[i[0]]:
            if t == '_':
                t = ''
            for q in qualifiers:
                qual = safe_map[i[0]]
                if invert:
                    qual = invert_safe[qual]

                if (not invert or qual):
                    file = prefix_safe + '/' + name + '-' + invert + '-' + q + qual + '-' + 'rule-' + i + t + '.sd'
                    gen_file(file, xres, 0, '%s %s' % (q, qual), rule1, i, t, 1, q, rule2, i, t)

                    file = prefix_safe + '/' + name + '-' + invert + '-' + q + qual + i + '-' + 'rule-' + t + '.sd'
                    gen_file(file, xres, 0, q, rule1, i, t, 1, '%s %s' % (q, qual), rule2, i, t)


test_gen_list()

gen_conflicting_x()
gen_overlap_re_exact()
gen_dominate_re_re()
gen_ambiguous_re_re()
gen_leading_perms("exact", "/bin/cat", "/bin/cat")
gen_leading_perms("exact-re", "/bin/*", "/bin/*")
gen_leading_perms("overlap", "/*", "/bin/cat")
gen_leading_perms("dominate", "/**", "/*")
gen_leading_perms("ambiguous", "/a*", "/*b")
gen_safe_perms("exact", "PASS", "", "/bin/cat", "/bin/cat")
gen_safe_perms("exact-re", "PASS", "", "/bin/*", "/bin/*")
gen_safe_perms("overlap", "PASS", "", "/*", "/bin/cat")
gen_safe_perms("dominate", "PASS", "", "/**", "/*")
gen_safe_perms("ambiguous", "PASS", "", "/a*", "/*b")
gen_safe_perms("exact", "FAIL", "inv", "/bin/cat", "/bin/cat")
gen_safe_perms("exact-re", "FAIL", "inv", "/bin/*", "/bin/*")
gen_safe_perms("overlap", "PASS", "inv", "/*", "/bin/cat")
gen_safe_perms("dominate", "FAIL", "inv", "/**", "/*")
gen_safe_perms("ambiguous", "FAIL", "inv", "/a*", "/*b")

print ("Generated %s xtransition interaction tests" % count)
