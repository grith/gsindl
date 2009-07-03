from setuptools import setup, find_packages
import os

version = '1.0'

setup(name='arcs.gsi',
      version=version,
      description="",
      long_description=open(os.path.join("README")).read() + "\n" +
                       open(os.path.join("CHANGES")).read(),
      # Get more strings from http://www.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        ],
      keywords='',
      author='Russell Sim',
      author_email='russell.sim@arcs.org.au',
      url='',
      license='GPL',
      packages=find_packages('src', exclude=['ez_setup']),
      package_dir = {'': 'src'},
      namespace_packages=['arcs'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'setuptools',
          'M2Crypto',
          # -*- Extra requirements: -*-
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
