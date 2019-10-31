"""A setuptools based setup module.
See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""
import sys
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand
from os import path


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass into py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest

        errno = pytest.main([])
        sys.exit(errno)


here = path.abspath(path.dirname(__file__))

about = {}
with open(path.join(here, 'seclytics', '__version__.py'), 'r') as f:
    exec(f.read(), about)

requires = ['requests', 'texttable', 'pprint', 'pybloomfiltermmap', 'ipaddress',
            'six']

test_require = requires + ['pytest']

setup(
    name=about['__title__'],
    include_package_data=True,
    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version=about['__version__'],
    description=about['__description__'],
    long_description='Get threat intelligence on IPs, CIDRs, ASNs and Files using Seclytics.',

    # The project's main homepage.
    url=about['__url__'],
    entry_points = {
        'console_scripts': ['seclytics_db_download=seclytics.scripts.download_db:main'],
    },
    # Author details
    cmdclass={'test': PyTest},
    author=about['__author__'],
    author_email=about['__author_email__'],
    packages=find_packages(),
    license=about['__license__'],
    install_requires=requires,
    tests_require=test_require,
)
