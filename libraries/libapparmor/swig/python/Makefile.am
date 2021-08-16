if HAVE_PYTHON

COMMONDIR = $(top_srcdir)/../../common/
include $(COMMONDIR)/Make.rules

EXTRA_DIST      = libapparmor_wrap.c

SUBDIRS = test

libapparmor_wrap.c: $(srcdir)/../SWIG/libapparmor.i
	$(SWIG) -python -I$(srcdir)/../../include -module LibAppArmor -o $@ $(srcdir)/../SWIG/libapparmor.i

MOSTLYCLEANFILES=libapparmor_wrap.c LibAppArmor.py

all-local: libapparmor_wrap.c setup.py
	if test ! -f libapparmor_wrap.c; then cp $(srcdir)/libapparmor_wrap.c . ; fi
	CC="$(CC)" CFLAGS="$(PYTHON_CPPFLAGS) $(EXTRA_WARNINGS)" LDSHARED="$(CC) -shared" LDFLAGS="$(PYTHON_LDFLAGS) $(LDFLAGS)" $(PYTHON) setup.py build

install-exec-local:
	$(PYTHON) setup.py install --root="/$(DESTDIR)" --prefix="$(prefix)"

clean-local:
	if test -x "$(PYTHON)"; then $(PYTHON) setup.py clean; fi
	rm -rf build
	if test $(top_srcdir) != $(top_builddir) ; then rm -f libapparmor_wrap.c ; fi

endif
