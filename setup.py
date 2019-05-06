from os import system
from os import listdir
from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

if 'impacket' not in listdir('./'):
    system('bash setup/setup.sh')

setup(
    name='ldap_search',
    version='0.1.0',
    author = 'm8r0wn',
    author_email = 'm8r0wn@protonmail.com',
    description = 'Perform LDAP queries against Windows environments',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/m8r0wn/ldap_search',
    license='GNU v3',
    packages=['ldap_search'],
    classifiers = [
        "Environment :: Console",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Topic :: Security"
    ],
    entry_points= {
        'console_scripts': ['ldap_search=ldap_search:main']
    }
)