#!/usr/bin/python
# coding=utf-8

import os, hashlib, base64
from pkcs7verify import check_sig
from apkfile import ApkFile, is_zipfile

DEBUG = False


def mf2dict(buf):
    mf_dict = {}
    idx = buf.find("\r\n\r\n")
    if idx > 0:
        s = "\r\n"
    else:
        s = "\n"
    b = buf.split(s * 2)
    for o in b:
        o = o.strip()
        # print o
        if len(o) > 0:
            d = dict(map(lambda z: (z[0], z[1]), filter(lambda y: len(y) == 2, map(lambda x: x.split(": ", 1),
                                                                                   o.replace(s + " ", "").split(s)))))
            if d.has_key("Name"):
                k = d["Name"]
            elif d.has_key("Signature-Version"):
                k = "META-INF/MANIFEST.MF"
            elif d.has_key("Manifest-Version"):
                k = None
            else:
                k = None
            if k:
                d["buf"] = o + s * 2
                d["buf2"] = o.replace(s + " ", "") + s * 2
                if not mf_dict.has_key(k):
                    mf_dict[k] = d
                else:
                    raise Exception("dup in manifest.mf")
    return mf_dict


def verifyjar(jarfile):
    verify = []
    if is_zipfile(jarfile):
        zfile = ApkFile(jarfile, 'r')
        if True:
            # try:
            sigfile = []
            dupfile = {}
            mf_dict = mf2dict(zfile.read("META-INF/MANIFEST.MF"))
            # print mf_dict
            for zipInfo in zfile.infolist():
                filename = zipInfo.filename
                #print filename
                if filename.endswith("/"):
                    continue
                if not dupfile.has_key(filename):
                    dupfile[filename] = 1
                else:
                    dupfile[filename] += 1
                    raise Exception("dup files in zip ")
                if filename.startswith("META-INF/"):
                    sigfile.append(filename)
                else:
                    if mf_dict.has_key(filename):
                        mf_data = mf_dict[filename]
                        #print mf_data
                        if mf_data.has_key("SHA1-Digest"):
                            if hashlib.sha1(zfile.read(filename)).digest() == base64.decodestring(
                                    mf_data["SHA1-Digest"]):
                                pass
                            else:
                                raise Exception("file hash error")
                        else:
                            raise Exception("unknown hash type")
                    else:
                        print filename
                        raise Exception("file not in hashed list")
            if len(list(set(mf_dict.keys()).difference(set(dupfile.keys())))) > 0:
                raise Exception("file in hashed list lost")
            for sig in sigfile:
                if sig.endswith(".DSA") or sig.endswith(".RSA"):
                    try:
                        sigbuf = zfile.read(sig)
                        sfbuf = zfile.read(sig[:-3] + "SF")
                        sfdic = mf2dict(sfbuf)
                        mfv = sfdic.pop("META-INF/MANIFEST.MF")
                        if mfv.has_key("SHA1-Digest-Manifest"):
                            if hashlib.sha1(zfile.read("META-INF/MANIFEST.MF")).digest() == base64.decodestring(
                                    mfv["SHA1-Digest-Manifest"]):
                                pass
                            else:
                                raise Exception("mf hash lost")
                        else:
                            raise Exception("unknown hash type")
                        for sfk, sfv in sfdic.items():
                            if mf_dict.has_key(sfk):
                                if sfv.has_key("SHA1-Digest"):
                                    if hashlib.sha1(mf_dict[sfk]["buf"]).digest() == base64.decodestring(
                                            sfv["SHA1-Digest"]):
                                        pass
                                    elif hashlib.sha1(mf_dict[sfk]["buf2"]).digest() == base64.decodestring(
                                            sfv["SHA1-Digest"]):
                                        pass
                                    else:
                                        raise Exception("line hash error")
                                else:
                                    raise Exception("unknown hash type")
                            else:
                                raise Exception("line not in hashed list")
                        if len(list(set(sfdic.keys()).difference(set(mf_dict.keys())))) > 0:
                            raise Exception("line in hashed list lost")
                        this_vefiry = check_sig(sigbuf, sfbuf)
                        if this_vefiry[0][0][0]:
                            verify.append([sig, this_vefiry])
                    except Exception, e:
                        print e
        # except Exception,e:
        # print e
        zfile.close()
    return verify


if __name__ == "__main__":
    testdir = r"g:\work\8\nocert_sample"
    for f in os.listdir(testdir):
        filepath = os.path.join(testdir, f)
        if not os.path.isfile(filepath):
            continue
        MAGIC = (lambda f: (f.read(2), f.close()))(open(filepath, "rb"))[0]
        if MAGIC != 'PK':
            continue
        print f,
        try:
            ret = verifyjar(filepath)
            print ret[0][1][0][0][0], ret[0][1][0][0][1], ret[0][1][0][0][2]
            if DEBUG:
                for sigfile, verify in ret:  # 不同的 rsa文件(的确有 多个rsa文件的可能)
                    print sigfile.ljust(79, "=")
                    for sigchain in verify:  # 签名信息(一般只有一个)
                        print "\t[chain]".ljust(79, "-")
                        for i in range(0, len(sigchain)):  #签名的证书链()
                            certmd5, certsub, certiss = sigchain[i]
                            print "\t\t[%2d] [certmd5]" % i, certmd5
                            print "\t\t\t [subject]", certsub
                            print "\t\t\t [ issuer]", certiss
        except Exception, e:
            print e
