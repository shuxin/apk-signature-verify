# apk-signature-verify

Jar Signature / APK Signature v2 verify with pure python (support rsa dsa ecdsa)

- require asn1crypto
- support verification for jar signature(apk signature v1),
- support verification for apk signature v2,
- support algorithm in rsa(md5/sha1/sha256/sha512),
- support algorithm in rsa+pss(sha256/sha512),
- support algorithm in dsa(sha1/sha256/sha512),
- support algorithm in ecdsa(sha256/sha512),
- support python2/python3,
- without build,
- without openssl/cryptography/M2Crypto,
- without any binary file like so/pyd/dll/dylib,

Read the test.py for how to use.

```python
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
            for one_chain in all_chain:
                print("\t[chain]".ljust(79, "-"))
                for i in range(0, len(one_chain)):
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
'''
(False, False)	empty-unsigned.apk
(False, False)	golden-aligned-in.apk
(True, True)	golden-aligned-out.apk
(True, False)	golden-aligned-v1-out.apk
(True, True)	golden-aligned-v1v2-out.apk
(False, True)	golden-aligned-v2-out.apk
(False, False)	golden-legacy-aligned-in.apk
(True, True)	golden-legacy-aligned-out.apk
(True, False)	golden-legacy-aligned-v1-out.apk
(True, True)	golden-legacy-aligned-v1v2-out.apk
(False, True)	golden-legacy-aligned-v2-out.apk
(True, True)	golden-rsa-minSdkVersion-1-out.apk
(True, True)	golden-rsa-minSdkVersion-18-out.apk
(True, True)	golden-rsa-minSdkVersion-24-out.apk
(True, True)	golden-rsa-out.apk
(False, False)	golden-unaligned-in.apk
(True, True)	golden-unaligned-out.apk
(True, False)	golden-unaligned-v1-out.apk
(True, True)	golden-unaligned-v1v2-out.apk
(False, True)	golden-unaligned-v2-out.apk
(True, False)	mismatched-compression-method.apk
(True, True)	original.apk
(True, True)	targetSandboxVersion-2.apk
(True, True)	two-signers-second-signer-v2-broken.apk
(True, True)	two-signers.apk
(False, False)	unsigned-targetSandboxVersion-2.apk
(True, False)	v1-only-empty.apk
(True, False)	v1-only-max-sized-eocd-comment.apk
(True, False)	v1-only-pkcs7-cert-bag-first-cert-not-used.apk
(True, False)	v1-only-targetSandboxVersion-2.apk
(True, False)	v1-only-two-signers.apk
(True, False)	v1-only-with-cr-in-entry-name.apk
(True, False)	v1-only-with-dsa-sha1-1.2.840.10040.4.1-1024.apk
(True, False)	v1-only-with-dsa-sha1-1.2.840.10040.4.1-2048.apk
(True, False)	v1-only-with-dsa-sha1-1.2.840.10040.4.1-3072.apk
(True, False)	v1-only-with-dsa-sha1-1.2.840.10040.4.3-1024.apk
(True, False)	v1-only-with-dsa-sha1-1.2.840.10040.4.3-2048.apk
(True, False)	v1-only-with-dsa-sha1-1.2.840.10040.4.3-3072.apk
(True, False)	v1-only-with-dsa-sha224-1.2.840.10040.4.1-1024.apk
(True, False)	v1-only-with-dsa-sha224-1.2.840.10040.4.1-2048.apk
(True, False)	v1-only-with-dsa-sha224-1.2.840.10040.4.1-3072.apk
(True, False)	v1-only-with-dsa-sha224-2.16.840.1.101.3.4.3.1-1024.apk
(True, False)	v1-only-with-dsa-sha224-2.16.840.1.101.3.4.3.1-2048.apk
(True, False)	v1-only-with-dsa-sha224-2.16.840.1.101.3.4.3.1-3072.apk
(True, False)	v1-only-with-dsa-sha256-1.2.840.10040.4.1-1024.apk
(True, False)	v1-only-with-dsa-sha256-1.2.840.10040.4.1-2048.apk
(True, False)	v1-only-with-dsa-sha256-1.2.840.10040.4.1-3072.apk
(True, False)	v1-only-with-dsa-sha256-2.16.840.1.101.3.4.3.2-1024.apk
(True, False)	v1-only-with-dsa-sha256-2.16.840.1.101.3.4.3.2-2048.apk
(True, False)	v1-only-with-dsa-sha256-2.16.840.1.101.3.4.3.2-3072.apk
(True, False)	v1-only-with-dsa-sha384-2.16.840.1.101.3.4.3.3-1024.apk
(True, False)	v1-only-with-dsa-sha384-2.16.840.1.101.3.4.3.3-2048.apk
(True, False)	v1-only-with-dsa-sha384-2.16.840.1.101.3.4.3.3-3072.apk
(True, False)	v1-only-with-dsa-sha512-2.16.840.1.101.3.4.3.4-1024.apk
(True, False)	v1-only-with-dsa-sha512-2.16.840.1.101.3.4.3.4-2048.apk
(True, False)	v1-only-with-dsa-sha512-2.16.840.1.101.3.4.3.4-3072.apk
(True, False)	v1-only-with-ecdsa-sha1-1.2.840.10045.2.1-p256.apk
(True, False)	v1-only-with-ecdsa-sha1-1.2.840.10045.2.1-p384.apk
(True, False)	v1-only-with-ecdsa-sha1-1.2.840.10045.2.1-p521.apk
(True, False)	v1-only-with-ecdsa-sha1-1.2.840.10045.4.1-p256.apk
(True, False)	v1-only-with-ecdsa-sha1-1.2.840.10045.4.1-p384.apk
(True, False)	v1-only-with-ecdsa-sha1-1.2.840.10045.4.1-p521.apk
(True, False)	v1-only-with-ecdsa-sha224-1.2.840.10045.2.1-p256.apk
(True, False)	v1-only-with-ecdsa-sha224-1.2.840.10045.2.1-p384.apk
(True, False)	v1-only-with-ecdsa-sha224-1.2.840.10045.2.1-p521.apk
(True, False)	v1-only-with-ecdsa-sha224-1.2.840.10045.4.3.1-p256.apk
(True, False)	v1-only-with-ecdsa-sha224-1.2.840.10045.4.3.1-p384.apk
(True, False)	v1-only-with-ecdsa-sha224-1.2.840.10045.4.3.1-p521.apk
(True, False)	v1-only-with-ecdsa-sha256-1.2.840.10045.2.1-p256.apk
(True, False)	v1-only-with-ecdsa-sha256-1.2.840.10045.2.1-p384.apk
(True, False)	v1-only-with-ecdsa-sha256-1.2.840.10045.2.1-p521.apk
(True, False)	v1-only-with-ecdsa-sha256-1.2.840.10045.4.3.2-p256.apk
(True, False)	v1-only-with-ecdsa-sha256-1.2.840.10045.4.3.2-p384.apk
(True, False)	v1-only-with-ecdsa-sha256-1.2.840.10045.4.3.2-p521.apk
(True, False)	v1-only-with-ecdsa-sha384-1.2.840.10045.2.1-p256.apk
(True, False)	v1-only-with-ecdsa-sha384-1.2.840.10045.2.1-p384.apk
(True, False)	v1-only-with-ecdsa-sha384-1.2.840.10045.2.1-p521.apk
(True, False)	v1-only-with-ecdsa-sha384-1.2.840.10045.4.3.3-p256.apk
(True, False)	v1-only-with-ecdsa-sha384-1.2.840.10045.4.3.3-p384.apk
(True, False)	v1-only-with-ecdsa-sha384-1.2.840.10045.4.3.3-p521.apk
(True, False)	v1-only-with-ecdsa-sha512-1.2.840.10045.2.1-p256.apk
(True, False)	v1-only-with-ecdsa-sha512-1.2.840.10045.2.1-p384.apk
(True, False)	v1-only-with-ecdsa-sha512-1.2.840.10045.2.1-p521.apk
(True, False)	v1-only-with-ecdsa-sha512-1.2.840.10045.4.3.4-p256.apk
(True, False)	v1-only-with-ecdsa-sha512-1.2.840.10045.4.3.4-p384.apk
(True, False)	v1-only-with-ecdsa-sha512-1.2.840.10045.4.3.4-p521.apk
(True, False)	v1-only-with-lf-in-entry-name.apk
(True, False)	v1-only-with-nul-in-entry-name.apk
(True, False)	v1-only-with-rsa-1024-cert-not-der.apk
(True, False)	v1-only-with-rsa-1024-cert-not-der2.apk
(True, False)	v1-only-with-rsa-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.1-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.1-16384.apk
(True, False)	v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.1-2048.apk
(True, False)	v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.1-3072.apk
(True, False)	v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.1-4096.apk
(True, False)	v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.1-8192.apk
(True, False)	v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.4-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.4-16384.apk
(True, False)	v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.4-2048.apk
(True, False)	v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.4-3072.apk
(True, False)	v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.4-4096.apk
(True, False)	v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.4-8192.apk
(True, False)	v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.1-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.1-16384.apk
(True, False)	v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.1-2048.apk
(True, False)	v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.1-3072.apk
(True, False)	v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.1-4096.apk
(True, False)	v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.1-8192.apk
(True, False)	v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.5-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.5-16384.apk
(True, False)	v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.5-2048.apk
(True, False)	v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.5-3072.apk
(True, False)	v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.5-4096.apk
(True, False)	v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.5-8192.apk
(True, False)	v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.1-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.1-16384.apk
(True, False)	v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.1-2048.apk
(True, False)	v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.1-3072.apk
(True, False)	v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.1-4096.apk
(True, False)	v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.1-8192.apk
(True, False)	v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.14-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.14-16384.apk
(True, False)	v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.14-2048.apk
(True, False)	v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.14-3072.apk
(True, False)	v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.14-4096.apk
(True, False)	v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.14-8192.apk
(True, False)	v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.1-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.1-16384.apk
(True, False)	v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.1-2048.apk
(True, False)	v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.1-3072.apk
(True, False)	v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.1-4096.apk
(True, False)	v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.1-8192.apk
(True, False)	v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.11-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.11-16384.apk
(True, False)	v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.11-2048.apk
(True, False)	v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.11-3072.apk
(True, False)	v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.11-4096.apk
(True, False)	v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.11-8192.apk
(True, False)	v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.1-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.1-16384.apk
(True, False)	v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.1-2048.apk
(True, False)	v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.1-3072.apk
(True, False)	v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.1-4096.apk
(True, False)	v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.1-8192.apk
(True, False)	v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.12-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.12-16384.apk
(True, False)	v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.12-2048.apk
(True, False)	v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.12-3072.apk
(True, False)	v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.12-4096.apk
(True, False)	v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.12-8192.apk
(True, False)	v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.1-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.1-16384.apk
(True, False)	v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.1-2048.apk
(True, False)	v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.1-3072.apk
(True, False)	v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.1-4096.apk
(True, False)	v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.1-8192.apk
(True, False)	v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.13-1024.apk
(True, False)	v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.13-16384.apk
(True, False)	v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.13-2048.apk
(True, False)	v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.13-3072.apk
(True, False)	v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.13-4096.apk
(True, False)	v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.13-8192.apk
(False, False)	v1-only-with-signed-attrs-missing-content-type.apk
(False, False)	v1-only-with-signed-attrs-missing-digest.apk
(False, False)	v1-only-with-signed-attrs-multiple-good-digests.apk
(True, False)	v1-only-with-signed-attrs-signerInfo1-good-signerInfo2-good.apk
(True, False)	v1-only-with-signed-attrs-signerInfo1-missing-content-type-signerInfo2-good.apk
(True, False)	v1-only-with-signed-attrs-signerInfo1-missing-digest-signerInfo2-good.apk
(True, False)	v1-only-with-signed-attrs-signerInfo1-multiple-good-digests-signerInfo2-good.apk
(True, False)	v1-only-with-signed-attrs-signerInfo1-wrong-content-type-signerInfo2-good.apk
(True, False)	v1-only-with-signed-attrs-signerInfo1-wrong-digest-signerInfo2-good.apk
(True, False)	v1-only-with-signed-attrs-signerInfo1-wrong-order-signerInfo2-good.apk
(True, False)	v1-only-with-signed-attrs-signerInfo1-wrong-signature-signerInfo2-good.apk
(False, False)	v1-only-with-signed-attrs-wrong-content-type.apk
(False, False)	v1-only-with-signed-attrs-wrong-digest.apk
(False, False)	v1-only-with-signed-attrs-wrong-order.apk
(False, False)	v1-only-with-signed-attrs-wrong-signature.apk
(False, False)	v1-only-with-signed-attrs.apk
(False, False)	v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-manifest.apk
(False, False)	v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-sf.apk
(False, False)	v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-manifest.apk
(False, False)	v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-sf.apk
(True, False)	v1-sha1-sha256-manifest-and-sf.apk
(True, False)	v1-sha1-sha256-manifest-and-sha1-sf.apk
(True, False)	v1-with-apk-sig-block-but-without-apk-sig-scheme-v2-block.apk
(False, False)	v2-only-apk-sig-block-size-mismatch.apk
(False, False)	v2-only-cert-and-public-key-mismatch.apk
<class 'zipfile.BadZipFile'>	v2-only-garbage-between-cd-and-eocd.apk
(False, True)	v2-only-max-sized-eocd-comment.apk
(False, True)	v2-only-missing-classes.dex.apk
(False, False)	v2-only-no-certs-in-sig.apk
(False, False)	v2-only-signatures-and-digests-block-mismatch.apk
(False, True)	v2-only-targetSandboxVersion-2.apk
(False, True)	v2-only-targetSandboxVersion-3.apk
<class 'zipfile.BadZipFile'>	v2-only-truncated-cd.apk
(False, True)	v2-only-two-signers-second-signer-no-sig.apk
(False, True)	v2-only-two-signers-second-signer-no-supported-sig.apk
(False, True)	v2-only-two-signers.apk
(False, True)	v2-only-unknown-pair-in-apk-sig-block.apk
(False, False)	v2-only-with-dsa-sha256-1024-sig-does-not-verify.apk
(False, True)	v2-only-with-dsa-sha256-1024.apk
(False, True)	v2-only-with-dsa-sha256-2048.apk
(False, True)	v2-only-with-dsa-sha256-3072.apk
(False, False)	v2-only-with-ecdsa-sha256-p256-digest-mismatch.apk
(False, False)	v2-only-with-ecdsa-sha256-p256-sig-does-not-verify.apk
(False, True)	v2-only-with-ecdsa-sha256-p256.apk
(False, True)	v2-only-with-ecdsa-sha256-p384.apk
(False, True)	v2-only-with-ecdsa-sha256-p521.apk
(False, True)	v2-only-with-ecdsa-sha512-p256.apk
(False, True)	v2-only-with-ecdsa-sha512-p384.apk
(False, True)	v2-only-with-ecdsa-sha512-p521.apk
(False, False)	v2-only-with-ignorable-unsupported-sig-algs.apk
(False, True)	v2-only-with-rsa-pkcs1-sha256-1024-cert-not-der.apk
(False, True)	v2-only-with-rsa-pkcs1-sha256-1024.apk
(False, True)	v2-only-with-rsa-pkcs1-sha256-16384.apk
(False, False)	v2-only-with-rsa-pkcs1-sha256-2048-sig-does-not-verify.apk
(False, True)	v2-only-with-rsa-pkcs1-sha256-2048.apk
(False, True)	v2-only-with-rsa-pkcs1-sha256-3072.apk
(False, True)	v2-only-with-rsa-pkcs1-sha256-4096.apk
(False, True)	v2-only-with-rsa-pkcs1-sha256-8192.apk
(False, True)	v2-only-with-rsa-pkcs1-sha512-1024.apk
(False, True)	v2-only-with-rsa-pkcs1-sha512-16384.apk
(False, True)	v2-only-with-rsa-pkcs1-sha512-2048.apk
(False, True)	v2-only-with-rsa-pkcs1-sha512-3072.apk
(False, False)	v2-only-with-rsa-pkcs1-sha512-4096-digest-mismatch.apk
(False, True)	v2-only-with-rsa-pkcs1-sha512-4096.apk
(False, True)	v2-only-with-rsa-pkcs1-sha512-8192.apk
(False, True)	v2-only-with-rsa-pss-sha256-1024.apk
(False, True)	v2-only-with-rsa-pss-sha256-16384.apk
(False, False)	v2-only-with-rsa-pss-sha256-2048-sig-does-not-verify.apk
(False, True)	v2-only-with-rsa-pss-sha256-2048.apk
(False, True)	v2-only-with-rsa-pss-sha256-3072.apk
(False, True)	v2-only-with-rsa-pss-sha256-4096.apk
(False, True)	v2-only-with-rsa-pss-sha256-8192.apk
(False, True)	v2-only-with-rsa-pss-sha512-16384.apk
(False, True)	v2-only-with-rsa-pss-sha512-2048.apk
(False, True)	v2-only-with-rsa-pss-sha512-3072.apk
(False, True)	v2-only-with-rsa-pss-sha512-4096.apk
(False, True)	v2-only-with-rsa-pss-sha512-8192.apk
(False, False)	v2-only-wrong-apk-sig-block-magic.apk
(True, False)	v2-stripped-with-ignorable-signing-schemes.apk
(True, False)	v2-stripped.apk
<class 'NotImplementedError'>	weird-compression-method.apk
'''
```