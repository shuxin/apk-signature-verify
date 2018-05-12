#!/usr/bin/python
# coding=utf-8

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

try:
    with open(path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except Exception as e:
    long_description = '''
Jar Signature / APK Signature v2 verify with pure python (support rsa dsa ecdsa)

require asn1crypto
support verification for jar signature(apk signature v1),
support verification for apk signature v2,
support algorithm in rsa(md5/sha1/sha256/sha512),
support algorithm in rsa+pss(sha256/sha512),
support algorithm in dsa(sha1/sha256/sha512),
support algorithm in ecdsa(sha256/sha512),
support python2/python3,
without build,
without openssl/cryptography/M2Crypto,
without any binary file like so/pyd/dll/dylib,    
'''

setup(
    name="apkverify",
    version="0.1.0.3",
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
