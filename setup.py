from setuptools import setup, find_packages
from xml.dom.minidom import parse
import os

ex_req = []
# a hack because redhat setuptools can't detect m2crypto
if not os.path.exists('/etc/redhat-release'):
    ex_req.append('M2Crypto')

# Get version from common file
pom = parse('pom.xml')
for t in pom.getElementsByTagName('project')[0].childNodes:
    if t.nodeName == 'version':
        version = t.childNodes[0].nodeValue.rstrip('-SNAPSHOT')
        break

setup(name='arcs.gsi',
      version=version,
      description="Library to assist GSI authentication and certificate handling in python.",
      long_description=".. contents::\n\n" +
                       open(os.path.join("docs", "introduction.rst")).read() + "\n" +
                       open(os.path.join("docs", "changes.rst")).read(),
      # Get more strings from http://www.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Topic :: Security :: Cryptography",
        "Intended Audience :: Developers",
        "Topic :: System :: Distributed Computing",
        ],
      keywords='',
      author='Russell Sim',
      author_email='russell.sim@arcs.org.au',
      url='http://code.arcs.org.au/gitorious/arcs-gsi/arcs-gsi',
      download_url='http://code.arcs.org.au/pypi/simple/arcs.gsi/',
      license='GPL',
      packages=find_packages('src/main/python', exclude=['ez_setup']),
      package_dir = {'': 'src/main/python'},
      namespace_packages=['arcs'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'setuptools',
          # -*- Extra requirements: -*-
      ] + ex_req,
      entry_points="""
      # -*- Entry points: -*-
      [console_scripts]
      proxy-init = arcs.gsi.proxyinit:main
      """,
      )
