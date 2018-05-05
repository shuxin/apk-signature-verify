#!/usr/bin/python
# coding=utf-8

import os
import sys
from apkverify import ApkSignature

if __name__ == "__main__":
    testdir = os.path.join(os.path.abspath("."),"apksig")
    log = open(testdir + ".py%d.txt" % (sys.version_info[0]), "wb")
    for filename in os.listdir(testdir):
        filepath = os.path.join(testdir, filename)
        if not os.path.isfile(filepath):
            continue
        MAGIC = (lambda f: (f.read(2), f.close()))(open(filepath, "rb"))[0]
        if MAGIC != b'PK':
            continue
        print("=" * 160)
        print(filepath)
        log_verify = None
        try:
            a = ApkSignature(os.path.abspath(filepath))
            print(a.apkpath)
            sigver = a.is_sigv2()
            v_auto = a.verify()  # auto check version
            v_ver1 = a.verify(1)  # force check version 1
            v_ver2 = a.verify(2)  # force check version 2
            print("Verify:", sigver, v_auto, v_ver1, v_ver2)
            log_verify = v_ver1 , v_ver2
            for line in a.errors:
                print("Error:", line)
            all_certs = a.all_certs()
            sig_certs = a.get_certs()
            all_chain = a.get_chains()
            print(all_certs)
            print(sig_certs)
            print(all_chain)
            all_certs = a.all_certs(readable=True)
            sig_certs = a.get_certs(readable=True)
            all_chain = a.get_chains(readable=True)
            print(all_certs)
            print(sig_certs)
            print(all_chain)
            for one_chain in all_chain:  # 签名信息(一般只有一个)
                print("\t[chain]".ljust(79, "-"))
                for i in range(0, len(one_chain)):  # 签名的证书链()
                    certprt, certsub, certiss = one_chain[i]
                    print("\t\t[%2d] [certprt]" % i, certprt)
                    print("\t\t\t [subject]", certsub)
                    print("\t\t\t [ issuer]", certiss)
        except Exception as e:
            import logging
            logging.exception(e)
            print(e)
            log_verify = type(e)
        log.write((u"%s\t%s\n" % (log_verify, filename)).encode("utf8"))
        log.flush()
    log.close()
