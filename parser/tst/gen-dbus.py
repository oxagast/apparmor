#!/usr/bin/python3
#
#   Copyright (c) 2013 Canonical, Ltd. (All rights reserved)
#   Copyright (c) 2021 Christian Boltz
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of version 2 of the GNU General Public
#   License published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, contact Canonical Ltd.
#

from testlib import write_file

def get_rule (quantifier, perms, session, name, path, interface, member, peer):

    result = ' '

    for part in [quantifier, 'dbus', perms, session, name, path, interface, member, peer]:
        if part:
            result += ' %s' % part

    result += ',\n'

    return result

def gen_file(test, xres, quantifier, perms, session, name, path, interface, member, peer):
    global count

    content = ''
    content += '#\n'
    content += '#=DESCRIPTION %s\n' % test
    content += '#=EXRESULT %s\n' % xres
    content += '#\n'
    content += '/usr/bin/foo {\n'
    content += get_rule(quantifier, perms, session, name, path, interface, member, peer)
    content += '}\n'

    write_file('simple_tests/generated_dbus', '%s-%s.sd' % (test, count), content)

    count += 1

def gen_files (test, xres, quantifiers, perms, sessions, names, paths, interfaces, members, peers):
    for quantifier in quantifiers:
        for perm in perms:
            for session in sessions:
                for name in names:
                    for path in paths:
                        for interface in interfaces:
                            for member in members:
                                for peer in peers:
                                    gen_file(test, xres, quantifier, perm, session, name, path, interface, member, peer)

count=0

quantifier = ['', 'deny', 'audit']
session = ['', 'bus=session', 'bus=system', 'bus=accessibility']
path = ['', 'path=/foo/bar', 'path="/foo/bar"']
interface = ['', 'interface=com.baz', 'interface="com.baz"']
member = ['', 'member=bar', 'member="bar"']

name = ['', 'name=com.foo', 'name="com.foo"']
peer = [
    'peer=()',
    'peer=(name=com.foo)',
    'peer=(name="com.foo")',
    'peer=(label=/usr/bin/app)',
    'peer=(label="/usr/bin/app")',
    'peer=(name=com.foo label=/usr/bin/app)',
    'peer=(name="com.foo" label="/usr/bin/app")',
]

# msg_perms are the permissions that are related to sending and receiving
# messages.
msg_perms = [
    '',
    'r',
    'w',
    'rw',
    'read',
    'receive',
    'write',
    'send',
    '(r)',
    '(w)',
    '(rw)',
    '(read)',
    '(receive)',
    '(write)',
    '(send)',
    '(write, read)',
    '(send receive)',
    '(send read)',
    '(receive write)',
]

gen_files('message-rules', 'PASS', quantifier, msg_perms, session,
	  [''], path, interface, member, peer)
gen_files('service-rules', 'PASS', quantifier, ['bind'], session,
	  name, [''], [''], [''], [''])
gen_files('eavesdrop-rules', 'PASS', quantifier, ['eavesdrop'], session,
	  [''], [''], [''], [''], [''])
gen_file('sloppy-formatting', 'PASS', '', '(send , receive )', 'bus=session',
	 '', 'path ="/foo/bar"', 'interface = com.foo', '  member=bar',
	 'peer =(   label= /usr/bin/app name  ="com.foo")')
gen_file('sloppy-formatting', 'PASS', '', 'bind', 'bus =session',
	 'name= com.foo', '', '', '', '')
gen_file('sloppy-formatting', 'PASS', '', 'eavesdrop', 'bus = system',
	 '', '', '', '', '')

# Don't use the empty element from each array since all empty conditionals would PASS but we want all FAILs
msg_perms.remove('')
name.remove('')
path.remove('')
interface.remove('')
member.remove('')
peer.remove('peer=()')

gen_files('message-incompat', 'FAIL', quantifier, msg_perms, session, name, [''], [''], [''], [''])
gen_files('service-incompat', 'FAIL', quantifier, ['bind'], session, name, path, [''], [''], [''])
gen_files('service-incompat', 'FAIL', quantifier, ['bind'], session, name, [''], interface, [''], [''])
gen_files('service-incompat', 'FAIL', quantifier, ['bind'], session, name, [''], [''], member, [''])
gen_files('service-incompat', 'FAIL', quantifier, ['bind'], session, name, [''], [''], [''], peer)
gen_files('eavesdrop-incompat', 'FAIL', quantifier, ['eavesdrop'], session, name, path, interface, member, peer)

gen_files('pairing-unsupported', 'FAIL', quantifier, ['send', 'bind'],
	  session, ['name=sn', 'label=sl'], [''], [''], [''],
	  ['peer=(name=pn)', 'peer=(label=pl)'])

# missing bus= prefix
gen_file('bad-formatting', 'FAIL', '', 'send', 'session', '', '', '', '', '')
# incorrectly formatted permissions
gen_files('bad-perms', 'FAIL', [''], ['send receive', '(send', 'send)'],
	  ['bus=session'], [''], [''], [''], [''], [''])
# invalid permissions
gen_files('bad-perms', 'FAIL', [''],
	  ['a', 'x', 'Ux', 'ix', 'm', 'k', 'l', '(a)', '(x)'], [''], [''],
	  [''], [''], [''], [''])

gen_file('duplicated-conditionals', 'FAIL', '', 'bus=1 bus=2', '', '', '', '', '', '')
gen_file('duplicated-conditionals', 'FAIL', '', 'name=1 name=2', '', '', '', '', '', '')
gen_file('duplicated-conditionals', 'FAIL', '', 'path=1 path=2', '', '', '', '', '', '')
gen_file('duplicated-conditionals', 'FAIL', '', 'interface=1 interface=2', '', '', '', '', '', '')
gen_file('duplicated-conditionals', 'FAIL', '', 'member=1 member=2', '', '', '', '', '', '')
gen_file('duplicated-conditionals', 'FAIL', '', 'peer=(name=1) peer=(name=2)', '', '', '', '', '', '')
gen_file('duplicated-conditionals', 'FAIL', '', 'peer=(label=1) peer=(label=2)', '', '', '', '', '', '')
gen_file('duplicated-conditionals', 'FAIL', '', 'peer=(name=1) peer=(label=2)', '', '', '', '', '', '')

print('Generated %s dbus tests' % count)
