# ----------------------------------------------------------------------
#    Copyright (c) 1999, 2004-2009 NOVELL (All rights reserved)
#    Copyright (c) 2010-2016 Canonical Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, contact Novell, Inc.
# ----------------------------------------------------------------------
NAME 		= apparmor-utils
all:
COMMONDIR=../common/

include $(COMMONDIR)/Make.rules

PYTOOLS = aa-easyprof aa-genprof aa-logprof aa-cleanprof aa-mergeprof \
          aa-autodep aa-audit aa-complain aa-enforce aa-disable \
	        aa-notify aa-unconfined
TOOLS = ${PYTOOLS} aa-decode aa-remove-unknown
PYSETUP = python-tools-setup.py
PYMODULES = $(wildcard apparmor/*.py apparmor/rule/*.py)

MANPAGES = ${TOOLS:=.8} logprof.conf.5

PYFLAKES ?= pyflakes3

all: docs
	$(MAKE) -C po all
	$(MAKE) -C vim all

.PHONY: docs
docs: ${MANPAGES} ${HTMLMANPAGES}

# need some better way of determining this
DESTDIR=/
BINDIR=${DESTDIR}/usr/sbin
CONFDIR=${DESTDIR}/etc/apparmor
PYPREFIX=/usr


po/${NAME}.pot: ${TOOLS} ${PYMODULES}
	$(MAKE) -C po ${NAME}.pot NAME=${NAME} SOURCES="${TOOLS} ${PYMODULES}"

.PHONY: install
install: ${MANPAGES} ${HTMLMANPAGES}
	install -d ${CONFDIR}
	install -m 644 logprof.conf severity.db notify.conf ${CONFDIR}
	install -d ${BINDIR}
	# aa-easyprof is installed by python-tools-setup.py
	install -m 755 $(filter-out aa-easyprof, ${TOOLS}) ${BINDIR}
	$(MAKE) -C po install DESTDIR=${DESTDIR} NAME=${NAME}
	$(MAKE) install_manpages DESTDIR=${DESTDIR}
	$(MAKE) -C vim install DESTDIR=${DESTDIR}
	${PYTHON} ${PYSETUP} install --prefix=${PYPREFIX} --root=${DESTDIR} --version=${VERSION}

.PHONY: clean
ifndef VERBOSE
.SILENT: clean
endif
clean: pod_clean
	rm -f core core.* *.o *.s *.a *~
	$(MAKE) -C po clean
	$(MAKE) -C vim clean
	$(MAKE) -C test clean
	rm -rf staging/ build/
	rm -f apparmor/*.pyc apparmor/rule/*.pyc
	rm -rf apparmor/__pycache__/ apparmor/rule/__pycache__/

# ${CAPABILITIES} is defined in common/Make.rules
.PHONY: check_severity_db
.SILENT: check_severity_db
check_severity_db: /usr/include/linux/capability.h severity.db
	# The sed statement is based on the one in the parser's makefile
	RC=0 ; for cap in $(shell ../common/list_capabilities.sh) ; do \
	    if !  grep -q -w $${cap} severity.db ; then \
		echo "ERROR: capability $${cap} not found in severity.db" ; \
		RC=1 ; \
	    fi ;\
	done ; \
	test "$$RC" -eq 0

# check_pod_files is defined in common/Make.rules
.PHONY: check_lint
.SILENT: check_lint
check_lint:
	for i in ${PYTOOLS} apparmor test/*.py; do \
		echo Checking $$i; \
		$(PYFLAKES) $$i || exit 1; \
	done

# check_pod_files is defined in common/Make.rules
.PHONY: check
.SILENT: check
check: check_severity_db check_pod_files check_lint
	$(MAKE) -C test check
	$(MAKE) -C vim check
