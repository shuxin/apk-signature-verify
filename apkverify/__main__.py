#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, print_function

import os
import sys
import argparse

try:
    from .metadata import __version__
    from .check_apk import is_apk_file
except (ValueError, ImportError):
    from metadata import __version__
    from check_apk import is_apk_file

if sys.version_info < (3,):
    basestring_cls = (unicode, str)
else:
    basestring_cls = (str, bytes)


def apk_check(args):
    if isinstance(args.path, basestring_cls) and \
            args.path and os.path.exists(args.path):
        check_files = []
        if os.path.isdir(args.path):
            for root, dirs, files in os.walk(args.path):
                for item_file in files:
                    check_files.append(os.path.join(root, item_file))
        else:
            check_files.append(args.path)
        for item_file in check_files:
            lite_result_check, lite_errors = is_apk_file(item_file)
            if lite_result_check:
                full_result_check, full_errors = is_apk_file(item_file, validate=True)
                print(
                    'Check file APK {0} : is apk - {1} , valid sign - {2}'.format(
                        item_file, lite_result_check, full_result_check))
            else:
                print(
                    'Check file APK {0} : invalid.'.format(item_file))
    else:
        print('Error. path for check APK not found - {0}'.format(args.path))


def get_parser():
    parser = argparse.ArgumentParser(
        prog='python -m apkverify',
        description='Help for work with Apkverify version {}'.format(__version__),
        usage='%(prog)s [-h] [options]',
        add_help=True, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        '-p', '--path', action='store', type=str, help='path for target file or dir')

    parser.add_argument(
        '--version', action='version',
        version='Apkverify version {}'.format(__version__))

    parser.set_defaults(func=apk_check)
    help_message = parser.format_help() + '\n '
    parser.epilog = help_message

    return parser.parse_args()


if __name__ == '__main__':
    args = get_parser()
    args.func(args)
