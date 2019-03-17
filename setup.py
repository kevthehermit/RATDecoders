#!/usr/bin/env python
from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='malwareconfig',
    version='0.0.8',
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
    scripts=['malwareconfig.py'],
    package_data={'': ['*.yar', 'README.md, LICENSE']}
)
