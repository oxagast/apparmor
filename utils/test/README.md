# Running individual tests

Python's unittest allows individual tests to be executed by specifying the class name and the test on the command line.
When running tests individually, the unittest framework executes the "setUp" and "tearDown" methods automatically.
For more information, refer to the [unittest documentation](https://docs.python.org/3/library/unittest.html).

Make sure to set the environment variables pointing to the in-tree apparmor modules, and the in-tree libapparmor and its python wrapper:

```bash
$ export PYTHONPATH=..:../../libraries/libapparmor/swig/python/build/$(/usr/bin/python3 -c "import distutils.util; import platform; print(\"lib.%s-%s\" %(distutils.util.get_platform(), platform.python_version()[:3]))")
$ export __AA_CONFDIR=.
```

To execute the test individually, run:

```bash
$ python3 ./test-tile.py ClassFoo.test_bar
```