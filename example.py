#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, print_function

import os

try:
    from .apkverify.check_apk import is_apk_file
    from .apkverify import ApkSignature
except (ValueError, ImportError):
    from apkverify.check_apk import is_apk_file
    from apkverify import ApkSignature


def check_default():
    base_dir = os.path.abspath(os.path.dirname(__file__))
    apk_path = os.path.join(base_dir, 'test/valid/com.android.vending-16.apk')
    apk = ApkSignature(apk_path)
    print('    File: {}'.format(apk.apkpath))
    signature_version = apk.is_sigv2()
    v_auto = apk.verify()  # auto check version
    v_ver1 = apk.verify(1)  # force check version 1
    v_ver2 = apk.verify(2)  # force check version 2
    print('    Verify: {}, {}, {}, {}'.format(signature_version, v_auto, v_ver1, v_ver2))
    for line in apk.errors:
        print('    Error: {}'.format(line))
    all_certs = apk.all_certs()
    sig_certs = apk.get_certs()
    all_chain = apk.get_chains()
    print('    {}'.format(all_certs))
    print('    {}'.format(sig_certs))
    print('    {}'.format(all_chain))
    all_certs = apk.all_certs(readable=True)
    sig_certs = apk.get_certs(readable=True)
    all_chain = apk.get_chains(readable=True)
    print('    {}'.format(all_certs))
    print('    {}'.format(sig_certs))
    print('    {}'.format(all_chain))


def test_apk(type_files='valid'):
    base_dir = os.path.abspath(os.path.dirname(__file__))
    apk_dir = os.path.join(base_dir, 'test/{}/'.format(type_files))
    for item in os.listdir(apk_dir):
        if item.endswith('.apk'):
            full_path_apk = os.path.join(apk_dir, item)
            lite_result_check, errors = is_apk_file(full_path_apk)
            full_result_check, errors = is_apk_file(full_path_apk, validate=True)
            print(
                '    Check file apk {0} : lite - {1} , full (with validate sign) - {2}'.format(
                    full_path_apk, lite_result_check, full_result_check))


def main():
    print('Default check.')
    check_default()
    print('Check valid files.')
    test_apk()
    print('Check invalid files.')
    test_apk('invalid')


if __name__ == "__main__":
    main()
