#!/usr/bin/python
# coding=utf-8

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="apkverify",
    version="0.1.0",
    description="Jar Signature / APK Signature v2 verify with PURE PYTHON",
    long_description=long_description,
    author="shuxin",
    author_email="shuxin@users.noreply.github.com",
    url="https://github.com/shuxin/apk-signature-verify",
    license="MIT",
    packages=["apkverify"],
    install_requires=['asn1crypto'],
    include_package_data = False,
    platforms = "any",
    keywords=["apk", "signature", "verify",],
)
