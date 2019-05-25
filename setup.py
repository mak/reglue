#!/usr/bin/env python2

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

def long_description():
    with open('README.rst') as f:
        d=f.read()
    return d

setup(name='REglue',
      version='0.0.1',
      description='Library providing common interface for RE frameworks',
      long_description='Library providing common interface for RE frameworks',
      author='Maciej Kotowicz',
      author_email='mak@lokalhost.pl',
      url='https://github.com/mak/reglue',
      package_dir={'reglue': 'src'},
      packages=['reglue', 'reglue.backend','reglue.common',
                'reglue.backend.ida',
                'reglue.backend.r2',
                'reglue.backend.binja',
                'reglue.backend.meng',
                'reglue.backend.nucleus',
                'reglue.backend.smda',
                'reglue.backend.ghidra',
      ],
)
