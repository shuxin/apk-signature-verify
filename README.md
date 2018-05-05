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