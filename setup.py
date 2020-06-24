#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", encoding='utf8') as fh:
    long_description = fh.read()

setup(
    name='malwareconfig',
    version='1.0.4',
    author='Kevin Breen',
    author_email='thehermit@malwareconfig.com',
    description="Malware Config Extraction",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://malwareconfig.com',
    license='GNU V3',
    zip_safe=False,
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'pefile',
        'pbkdf2',
        'javaobj-py3',
        'pycrypto',
        'androguard'
    ],
    scripts=['malconf'],
    package_data={'': ['*.yar', 'README.md, LICENSE']}
)
