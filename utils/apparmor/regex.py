# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2014-2015 Christian Boltz <apparmor@cboltz.de>
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

import re
from apparmor.common import AppArmorBug, AppArmorException

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()

## Profile parsing Regex
RE_AUDIT_DENY           = '^\s*(?P<audit>audit\s+)?(?P<allow>allow\s+|deny\s+)?'  # line start, optionally: leading whitespace, <audit> and <allow>/deny
RE_EOL                  = '\s*(?P<comment>#.*?)?\s*$'  # optional whitespace, optional <comment>, optional whitespace, end of the line
RE_COMMA_EOL            = '\s*,' + RE_EOL # optional whitespace, comma + RE_EOL

RE_PROFILE_NAME         = '(?P<%s>(\S+|"[^"]+"))'    # string without spaces, or quoted string. %s is the match group name
RE_PATH                 = '/\S*|"/[^"]*"'  # filename (starting with '/') without spaces, or quoted filename.
RE_PROFILE_PATH         = '(?P<%s>(' + RE_PATH + '))'  # quoted or unquoted filename. %s is the match group name
RE_PROFILE_PATH_OR_VAR  = '(?P<%s>(' + RE_PATH + '|@{\S+}\S*|"@{\S+}[^"]*"))'  # quoted or unquoted filename or variable. %s is the match group name
RE_SAFE_OR_UNSAFE       = '(?P<execmode>(safe|unsafe))'
RE_XATTRS               = '(\s+xattrs\s*=\s*\((?P<xattrs>([^)=]+(=[^)=]+)?\s?)+)\)\s*)?'
RE_FLAGS                = '(\s+(flags\s*=\s*)?\((?P<flags>[^)]+)\))?'

RE_PROFILE_END          = re.compile('^\s*\}' + RE_EOL)
RE_PROFILE_CAP          = re.compile(RE_AUDIT_DENY + 'capability(?P<capability>(\s+\S+)+)?' + RE_COMMA_EOL)
RE_PROFILE_ALIAS        = re.compile('^\s*alias\s+(?P<orig_path>"??.+?"??)\s+->\s*(?P<target>"??.+?"??)' + RE_COMMA_EOL)
RE_PROFILE_RLIMIT       = re.compile('^\s*set\s+rlimit\s+(?P<rlimit>[a-z]+)\s*<=\s*(?P<value>[^ ]+(\s+[a-zA-Z]+)?)' + RE_COMMA_EOL)
RE_PROFILE_BOOLEAN      = re.compile('^\s*(?P<varname>\$\{?\w*\}?)\s*=\s*(?P<value>true|false)\s*,?' + RE_EOL, flags=re.IGNORECASE)
RE_PROFILE_VARIABLE     = re.compile('^\s*(?P<varname>@\{?\w+\}?)\s*(?P<mode>\+?=)\s*(?P<values>@*.+?)' + RE_EOL)
RE_PROFILE_CONDITIONAL  = re.compile('^\s*if\s+(not\s+)?(\$\{?\w*\}?)\s*\{' + RE_EOL)
RE_PROFILE_CONDITIONAL_VARIABLE = re.compile('^\s*if\s+(not\s+)?defined\s+(@\{?\w+\}?)\s*\{\s*(#.*)?$')
RE_PROFILE_CONDITIONAL_BOOLEAN = re.compile('^\s*if\s+(not\s+)?defined\s+(\$\{?\w+\}?)\s*\{\s*(#.*)?$')
RE_PROFILE_NETWORK      = re.compile(RE_AUDIT_DENY + 'network(?P<details>\s+.*)?' + RE_COMMA_EOL)
RE_PROFILE_CHANGE_HAT   = re.compile('^\s*\^(\"??.+?\"??)' + RE_COMMA_EOL)
RE_PROFILE_HAT_DEF      = re.compile('^(?P<leadingspace>\s*)(?P<hat_keyword>\^|hat\s+)(?P<hat>\"??[^)]+?\"??)' + RE_FLAGS + '\s*\{' + RE_EOL)
RE_PROFILE_DBUS         = re.compile(RE_AUDIT_DENY + '(dbus\s*,|dbus(?P<details>\s+[^#]*)\s*,)' + RE_EOL)
RE_PROFILE_MOUNT        = re.compile(RE_AUDIT_DENY + '((mount|remount|umount|unmount)(\s+[^#]*)?\s*,)' + RE_EOL)
RE_PROFILE_SIGNAL       = re.compile(RE_AUDIT_DENY + '(signal\s*,|signal(?P<details>\s+[^#]*)\s*,)' + RE_EOL)
RE_PROFILE_PTRACE       = re.compile(RE_AUDIT_DENY + '(ptrace\s*,|ptrace(?P<details>\s+[^#]*)\s*,)' + RE_EOL)
RE_PROFILE_PIVOT_ROOT   = re.compile(RE_AUDIT_DENY + '(pivot_root\s*,|pivot_root\s+[^#]*\s*,)' + RE_EOL)
RE_PROFILE_UNIX         = re.compile(RE_AUDIT_DENY + '(unix\s*,|unix\s+[^#]*\s*,)' + RE_EOL)

# match anything that's not " or #, or matching quotes with anything except quotes inside
__re_no_or_quoted_hash = '([^#"]|"[^"]*")*'

RE_RULE_HAS_COMMA = re.compile('^' + __re_no_or_quoted_hash +
    ',\s*(#.*)?$')  # match comma plus any trailing comment
RE_HAS_COMMENT_SPLIT = re.compile('^(?P<not_comment>' + __re_no_or_quoted_hash + ')' + # store in 'not_comment' group
    '(?P<comment>#.*)$')  # match trailing comment and store in 'comment' group



RE_PROFILE_START          = re.compile(
    '^(?P<leadingspace>\s*)' +
    '(' +
        RE_PROFILE_PATH_OR_VAR % 'plainprofile' + # just a path
        '|' + # or
        '(' + 'profile' + '\s+' + RE_PROFILE_NAME % 'namedprofile' + '(\s+' + RE_PROFILE_PATH_OR_VAR % 'attachment' + ')?' + ')' + # 'profile', profile name, optionally attachment
    ')' +
    RE_XATTRS +
    RE_FLAGS +
    '\s*\{' +
    RE_EOL)


RE_PROFILE_CHANGE_PROFILE = re.compile(
    RE_AUDIT_DENY +
    'change_profile' +
    '(\s+' + RE_SAFE_OR_UNSAFE + ')?' +  # optionally exec mode
    '(\s+' + RE_PROFILE_PATH_OR_VAR % 'execcond' + ')?' +  # optionally exec condition
    '(\s+->\s*' + RE_PROFILE_NAME % 'targetprofile' + ')?' +  # optionally '->' target profile
    RE_COMMA_EOL)


# RE_PATH_PERMS is as restrictive as possible, but might still cause mismatches when adding different rule types.
# Therefore parsing code should match against file rules only after trying to match all other rule types.
RE_PATH_PERMS = '(?P<%s>[mrwalkPUCpucix]+)'

RE_PROFILE_FILE_ENTRY = re.compile(
    RE_AUDIT_DENY +
    '(?P<owner>owner\s+)?' +  # optionally: <owner>
    '(' +
        '(?P<bare_file>file)' +  # bare 'file,'
    '|' + # or
        '(?P<file_keyword>file\s+)?' +  # optional 'file' keyword
        '(' +
            RE_PROFILE_PATH_OR_VAR % 'path' + '\s+' + RE_PATH_PERMS % 'perms' +  # path and perms
        '|' +  # or
            RE_PATH_PERMS % 'perms2' + '\s+' + RE_PROFILE_PATH_OR_VAR % 'path2' +  # perms and path
        ')' +
        '(\s+->\s*' + RE_PROFILE_NAME % 'target' + ')?' +
    '|' + # or
        '(?P<link_keyword>link\s+)' +  # 'link' keyword
        '(?P<subset_keyword>subset\s+)?' +  # optional 'subset' keyword
        RE_PROFILE_PATH_OR_VAR % 'link_path' +  # path
        '\s+' + '->' + '\s+' +  # ' -> '
        RE_PROFILE_PATH_OR_VAR % 'link_target' +  # path
    ')' +
    RE_COMMA_EOL)


def parse_profile_start_line(line, filename):
    common_sections = [ 'leadingspace', 'flags', 'comment']

    sections = [ 'plainprofile', 'namedprofile', 'attachment', 'xattrs'] + common_sections
    matches = RE_PROFILE_START.search(line)

    if not matches:
        sections = ['hat_keyword', 'hat'] + common_sections
        matches = RE_PROFILE_HAT_DEF.search(line)

    if not matches:
        raise AppArmorBug('The given line from file %(filename)s is not the start of a profile: %(line)s' % { 'filename': filename, 'line': line } )

    result = {}

    for section in sections:
        if matches.group(section):
            result[section] = matches.group(section)

            # sections with optional quotes
            if section in ['plainprofile', 'namedprofile', 'attachment', 'hat']:
                result[section] = strip_quotes(result[section])
        else:
            result[section] = None

    if result['flags'] and result['flags'].strip() == '':
        raise AppArmorException(_('Invalid syntax in %(filename)s: Empty set of flags in line %(line)s.' % { 'filename': filename, 'line': line } ))

    result['is_hat'] = False
    if result.get('hat'):
        result['is_hat'] = True
        result['profile'] = result['hat']
        if result['hat_keyword'] == '^':
            result['hat_keyword'] = False
        else:
            result['hat_keyword'] = True
        result['profile_keyword'] = True
    elif result['plainprofile']:
        result['profile'] = result['plainprofile']
        result['profile_keyword'] = False
    else:
        result['profile'] = result['namedprofile']
        result['profile_keyword'] = True

    return result

RE_MAGIC_OR_QUOTED_PATH = '(<(?P<magicpath>.*)>|"(?P<quotedpath>.*)"|(?P<unquotedpath>[^<>"]*))'
RE_ABI = re.compile('^\s*#?abi\s*' + RE_MAGIC_OR_QUOTED_PATH + RE_COMMA_EOL)
RE_INCLUDE = re.compile('^\s*#?include(?P<ifexists>\s+if\s+exists)?\s*' + RE_MAGIC_OR_QUOTED_PATH + RE_EOL)

def re_match_include_parse(line, rule_name):
    '''Matches the path for include, include if exists and abi rules

    rule_name can be 'include' or 'abi'

    Returns a tuple with
    - if the "if exists" condition is given
    - the include/abi path
    - if the path is a magic path (enclosed in <...>)
    '''

    if rule_name == 'include':
        matches = RE_INCLUDE.search(line)
    elif rule_name == 'abi':
        matches = RE_ABI.search(line)
    else:
        raise AppArmorBug('re_match_include_parse() called with invalid rule name %s' % rule_name)

    if not matches:
        return None, None, None

    path = None
    ismagic = False
    if matches.group('magicpath'):
        path = matches.group('magicpath').strip()
        ismagic = True
    elif matches.group('unquotedpath'):
        path = matches.group('unquotedpath').strip()
        if re.search('\s', path):
            raise AppArmorException(_('Syntax error: %s must use quoted path or <...>') % rule_name)
        # LP: #1738879 - parser doesn't handle unquoted paths everywhere
        if rule_name == 'include':
            raise AppArmorException(_('Syntax error: %s must use quoted path or <...>') % rule_name)
    elif matches.group('quotedpath'):
        path = matches.group('quotedpath')
        # LP: 1738880 - parser doesn't handle relative paths everywhere, and
        # neither do we (see aa.py)
        if rule_name == 'include' and len(path) > 0 and path[0] != '/':
            raise AppArmorException(_('Syntax error: %s must use quoted path or <...>') % rule_name)

    # if path is empty or the empty string
    if path is None or path == "":
        raise AppArmorException(_('Syntax error: %s rule with empty filename') % rule_name)

    # LP: #1738877 - parser doesn't handle files with spaces in the name
    if rule_name == 'include' and re.search('\s', path):
        raise AppArmorException(_('Syntax error: %s rule filename cannot contain spaces') % rule_name)

    ifexists = False
    if rule_name == 'include' and matches.group('ifexists'):
        ifexists = True

    return path, ifexists, ismagic

def re_match_include(line):
    ''' return path of a 'include' rule '''
    (path, ifexists, ismagic) = re_match_include_parse(line, 'include')

    if not ifexists:
        return path

    return None

def strip_parenthesis(data):
    '''strips parenthesis from the given string and returns the strip()ped result.
       The parenthesis must be the first and last char, otherwise they won't be removed.
       Even if no parenthesis get removed, the result will be strip()ped.
       '''
    if data[0] + data[-1] == '()':
        return data[1:-1].strip()
    else:
        return data.strip()

def strip_quotes(data):
    if len(data) > 1 and data[0] + data[-1] == '""':
        return data[1:-1]
    else:
        return data
