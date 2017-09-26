#!/usr/bin/python
# coding=utf-8

import binascii
import hashlib
import struct
import math
import re
import os

from apkfile import ApkFile, is_zipfile
from pkcs7verify import check_sig, check_sig_v2

DEBUG = False

def __v1_jarmf2dict(buf):
    # print repr(buf)
    mf_dict = {}
    # idx = buf.find("\r\n\r\n")
    # if idx > 0:
    #     s = "\r\n"
    # else:
    #     s = "\n"
    # bl = buf.split(s * 2)
    bl = re.split('(\n\r\n|\n\n)', buf)
    bx = []
    for i in range(0,int(math.ceil(len(bl)*1.0/2))):
        bx.append("".join(bl[i*2:i*2+2]))
    # bl = re.split('\n\n', buf)
    # bl = re.findall(r"(\n\r\n|\n\n)(.*)(\n\r\n|\n\n)", buf, re.MULTILINE)
    # print bl
    # for b1 in bl:
    for b1 in bx:
        # print repr(b1)
        # bs = b1.strip()
        # if len(bs) > 0:
        if b1.strip():
            d = dict(map(lambda z: (z[0], z[1].rstrip()), filter(lambda y: len(y) == 2, map(lambda x: x.split(": ", 1), re.sub("(\r|)\n ", "", b1).strip().split("\n")))))
            # print d
            # d = dict(map(lambda z: (z[0], z[1]), filter(lambda y: len(y) == 2, map(lambda x: x.split(": ", 1), bs.replace(s + " ", "").split(s)))))
            if d.has_key("Name"):
                k = d["Name"]
            elif d.has_key("Signature-Version"):
                k = "META-INF/MANIFEST.MF"
            elif d.has_key("Manifest-Version"):
                k = None
            else:
                k = None
            if k:
                d["buf"] = b1
                d["buf2"] = re.sub("(\r|)\n ", "", b1)
                # d["buf"] = b1 + s * 2
                # d["buf2"] = b1.replace(s + " ", "") + s * 2
                if not mf_dict.has_key(k):
                    mf_dict[k] = d
                else:
                    # print k
                    raise Exception("dup in manifest.mf")
    return mf_dict

def __v1_hash_digest_verify(Attributes_attributes, String_entry, byte_data):
    for k,v in Attributes_attributes.items():
        if k.endswith(String_entry):
            x = k[:-len(String_entry)].upper()
            h = binascii.a2b_base64(v)
            if x == "SHA-512":
                return hashlib.sha512(byte_data).digest() == h
            elif x == "SHA-384":
                return hashlib.sha384(byte_data).digest() == h
            elif x == "SHA-256":
                return hashlib.sha256(byte_data).digest() == h
            elif x == "SHA1":
                return hashlib.sha1(byte_data).digest() == h
            else:
                return None
    return None

def __v1_jarverifymanifest(zfile):
    sigfile = []
    dupfile = {}
    try:
        mfbuff = zfile.read("META-INF/MANIFEST.MF")
        mf_dict = __v1_jarmf2dict(mfbuff)
    except Exception,e:
        # print e
        return "BadMF","",{},[]
    for zipInfo in zfile.infolist():
        # print repr(zipInfo.comment)
        filename = zipInfo.filename
        if type(filename) is str:
            filename_binary = filename
        elif type(filename) is unicode:
            filename_binary = filename.encode("utf8")
        else:
            filename_binary = str(filename)
        if filename_binary.endswith("/"):
            continue
        if not dupfile.has_key(filename_binary):
            dupfile[filename_binary] = 1
        else:
            dupfile[filename_binary] += 1
            return "DupEntry",mfbuff,{},[]
        if filename_binary.startswith("META-INF/"):
            sigfile.append(filename)
        else:
            if mf_dict.has_key(filename_binary):
                mf_data = mf_dict[filename_binary]
                buf = zfile.read(filename)
                vok = __v1_hash_digest_verify(mf_data,"-Digest",buf)
                if vok is None:
                    return "MFHashTypeError",mfbuff,{},[]
                elif vok == False:
                    return "MFFileHashError",mfbuff,{},[]
                else:
                    pass#True
            else:
                # print mf_dict
                print "MFFileHashLost",filename_binary
                #return "MFFileHashLost",mfbuff,{},[]
    lostfile = list(set(mf_dict.keys()).difference(set(dupfile.keys())))
    if len(lostfile) > 0:
        lostdexs = 0
        lostother = 0
        lostmeta = 0
        for filename_binary in lostfile:
            if "/" not in filename_binary and filename_binary.startswith("classes") and filename_binary.endswith(".dex"):
                lostdexs += 1
            elif filename_binary.startswith('META-INF/'):
                lostmeta += 1
            else:
                lostother += 1
        if lostother > 0:
            return "MFSomeFileLost", mfbuff, {}, []
        else:
            if lostdexs > 0:
                return "MFclassDexLost", mfbuff, {}, []

    return "OK",mfbuff,mf_dict,sigfile

def __v1_jarverifysigfile(zfile,mfbuff,mf_dict,sigfile):
    try:
        sfbuf = zfile.read(sigfile.rsplit(".",1)[0] + ".SF")
        sf_dic = __v1_jarmf2dict(sfbuf)
    except Exception,e:
        return "BadSF",""
    mfv = sf_dic.pop("META-INF/MANIFEST.MF",{})
    #ignore   "-Digest-Manifest-Main-Attributes"
    vok = __v1_hash_digest_verify(mfv, "-Digest-Manifest", mfbuff)
    if vok is True:
        #事实证明，这是个或选项。java(SignatureFileVerifier.java), android(JarVerifier.java) 都是
        return "OK",sfbuf
    if vok is None:
        pass#這個貌似不是必要選項
        # return "SFMFHashTypeError",""
    elif vok == False:
        pass#不再驗證不必要的 SHA1-Digest-Manifest-Main-Attributes 與 SHA1-Digest-Manifest 了
        #return "SFMFFileHashError",""
    else:
        pass#True
    for sfk, sfv in sf_dic.items():
        if sfk.startswith("META-INF/"):
            pass
        elif mf_dict.has_key(sfk):
            buff = mf_dict[sfk]["buf"]
            buf2 = mf_dict[sfk]["buf2"]
            digest_suffix = "-Digest"
            vok = __v1_hash_digest_verify(sfv, "-Digest", buff)
            if vok is None:
                digest_suffix = "-Digest-Manifest"
                vok = __v1_hash_digest_verify(sfv, "-Digest-Manifest", buff)
            if vok is None:
                return "SFHashTypeError",""
            elif vok == False:
                vok = __v1_hash_digest_verify(sfv, digest_suffix, buf2)
                if vok == False:
                    #print sfv
                    #print repr(buf2)
                    return "SFLineHashError",""
                else:
                    pass#None True
            else:
                pass#True
        else:
            return "SFLineHashLost",""
    lostline = list(set(mf_dict.keys()).difference(set(sf_dic.keys())))
    if len(lostline) > 0:
        lostother = 0
        lostmeta = 0
        for filename_binary in lostline:
            if filename_binary.startswith('META-INF/'):
                lostmeta += 1
            else:
                lostother += 1
        if lostother > 0:
            return "SFSomeLineLost",""
        else:
            pass
    return "OK",sfbuf

def verifysigv1(zfile):
    verify = []
    mfret,mfbuff,mf_dict,sigfile = __v1_jarverifymanifest(zfile)
    if mfret != "OK":
        ret = mfret
    else:
        ret = "NoSig"
        good_sfret = {}
        for sig in sigfile:
            if sig.endswith(".DSA") or sig.endswith(".RSA") or sig.endswith(".EC"):
                sfret,sfbuf = __v1_jarverifysigfile(zfile,mfbuff,mf_dict,sig)
                if sfret == "OK":
                    good_sfret[sig] = sfbuf
                else:
                    ret = sfret
        if len(good_sfret) > 0:
            ret = "NoCert"
            for sig,sfbuf in good_sfret.items():
                sigbuf = zfile.read(sig)
                ver_chain,all_certs,ver_certs,ext_certs,bad_certs = check_sig(sigbuf, sfbuf)
                if len(ver_certs)>0:
                    ret = "OK"
                    verify.append(ver_chain)
                else:
                    if ret != "OK":
                        ret = "BadCert"
    return ret, verify

def is_sigv2(zfile):
    v2 = False
    try:
        for zipInfo in zfile.infolist():
            # print repr(zipInfo.comment)
            filename = zipInfo.filename
            if type(filename) is str:
                filename_binary = filename
            elif type(filename) is unicode:
                filename_binary = filename.encode("utf8")
            else:
                filename_binary = str(filename)
            if filename_binary.endswith("/"):
                continue
            if filename_binary.startswith("META-INF/"):
                if filename_binary.endswith(".SF"):
                    for line in zfile.read(zipInfo).split("\n"):
                        if line.startswith("X-Android-APK-Signed:"):
                            line = line.split(":")[1].strip()
                            if line == '2':
                                v2 = True
    except Exception,e:
        ret = "ZipError"
    return v2

def __v2_zipfindsig(zfile):
    sigstart = -1
    offset_cd = -1
    cdend = -1
    filesize = -1
    APK_SIG_BLOCK_MIN_SIZE = 32
    v2sig = {}
    breakgotofail = True
    while breakgotofail:
        breakgotofail = False
        if (zfile.offset_cd < APK_SIG_BLOCK_MIN_SIZE):
            break
        zfile.fp.seek(0, 2)
        filesize = zfile.fp.tell()
        if offset_cd + zfile.size_cd > filesize:
            break
        offset_cd = zfile.offset_cd
        cdend = zfile.offset_cd + zfile.size_cd
        zfile.fp.seek(zfile.offset_cd - 24)
        buf = zfile.fp.read(24)
        if buf[8:] != 'APK Sig Block 42':
            break
        siginfoot = struct.unpack("Q",buf[:8])[0]
        if siginfoot < 24 or siginfoot > filesize:
            break
        sigstart = zfile.offset_cd - siginfoot - 8
        if sigstart < 0 or sigstart > filesize:
            break
        zfile.fp.seek(sigstart)
        buf = zfile.fp.read(siginfoot + 8)
        siginhead = struct.unpack("Q",buf[:8])[0]
        if siginfoot != siginhead:
            break
        idx = 8
        while idx + 12 <= siginhead - 24:
            l = struct.unpack("Q",buf[idx:idx+8])[0]
            i = struct.unpack("L",buf[idx+8:idx+12])[0]
            s = buf[idx+12:idx+12+l-4]
            v2sig[i] = s
            idx += 12
            idx += l - 4
            # buff2 = buf[idx:]
            # print repr(buff2)
        # print v2sig
    return v2sig, sigstart, offset_cd, cdend, filesize

def extract_list_by_int_prefix(data):
    datas = []
    idx = 0
    while idx + 4 <= len(data):
        i = struct.unpack("L",data[idx:idx+4])[0]
        s = data[idx+4:idx+4+i]
        idx += 4 + i
        datas.append(s)
        # print "debug",idx,len(data)
        # buff2 = sig[idx:]
        # print repr(buff2)
    if idx != len(data):
        print "warn",idx,len(data)
    return datas

def __v2_zipverify(zfile, sigstart, sigend, cdend, filesize, algs_for_zip_dict):
    READ = 1024 * 1024
    hashtypes = {}
    hashvalues = {}
    if algs_for_zip_dict:
        for hashtype, hashvalue in algs_for_zip_dict.items():
            # print hashtype,binascii.b2a_hex(hashvalue)
            if hashtype == "SHA256":
                hashtypes[hashtype] = hashlib.sha256
                hashvalues[hashtype] = []
            elif hashtype == "SHA512":
                hashtypes[hashtype] = hashlib.sha512
                hashvalues[hashtype] = []
            else:
                return False
        rl = [(0,sigstart), (sigend, cdend)]#, (cdend, filesize)]
        for _seek, _end in rl:
            zfile.fp.seek(_seek)
            while _seek < _end:
                _read = min(READ,_end-_seek)
                _buff = chr(0xa5) + struct.pack("L",_read) + zfile.fp.read(_read)
                for hashtype in algs_for_zip_dict.keys():
                    hb = hashtypes[hashtype](_buff).digest()
                    hashvalues[hashtype].append(hb)
                    # print _seek,_read,binascii.b2a_hex(hb)
                _seek += _read
        _seek, _end = cdend, filesize
        zfile.fp.seek(_seek)
        _eocd = zfile.fp.read()
        # _old_off = _eocd[16:16+4]
        _new_off = struct.pack("L",sigstart)
        # print "xxxxxxx",binascii.b2a_hex(_old_off)
        # print "xxxxxxx",binascii.b2a_hex(struct.pack("L",sigstart))
        # print "xxxxxxx",binascii.b2a_hex(struct.pack("L",sigend))
        _eocd = _eocd[:16] + _new_off + _eocd[16+4:]
        _seek, _end = 0,len(_eocd)
        while _seek < _end:
            _read = min(READ,_end-_seek)
            _buff = chr(0xa5) + struct.pack("L",_read) +_eocd[_seek:_seek+_read]
            for hashtype in algs_for_zip_dict.keys():
                hb = hashtypes[hashtype](_buff).digest()
                hashvalues[hashtype].append(hb)
                # print _seek,_read,binascii.b2a_hex(hb)
            _seek += _read
        for hashtype,hashvalue in algs_for_zip_dict.items():
            _buff = chr(0x5a) + struct.pack("L",len(hashvalues[hashtype])) + "".join(hashvalues[hashtype])
            hh = hashtypes[hashtype](_buff).digest()
            if hh != hashvalue:
                return False
        return True
    return False

def verifysigv2(zfile):
    verify = []
    sig, sigstart, sigend, cdend, filesize = __v2_zipfindsig(zfile)
    # print sig
    if not sig.has_key(0x7109871a):
        ret = "v2NoSig"
    else:
        ret = "v2BadSigData"
        for signers in extract_list_by_int_prefix(sig.get(0x7109871a)):
            for signer in extract_list_by_int_prefix(signers):
                # f = open("debug-xxx.txt","wb")
                # f.write(signer)
                # f.close()
                data = extract_list_by_int_prefix(signer)
                if len(data) >= 3:
                    signedData, signatures, publicKeyBytes = data[:3]
                    ret,algs_for_zip,ver_chain,all_certs,ver_certs,ext_certs,bad_certs = check_sig_v2(signedData, signatures, publicKeyBytes)
                    if ver_certs:
                        algs_for_zip_dict = {}
                        for hashtype,hashvalue in algs_for_zip:
                            if not algs_for_zip_dict.has_key(hashtype):
                                algs_for_zip_dict[hashtype] = hashvalue
                            else:
                                if algs_for_zip_dict[hashtype] != hashvalue:
                                    return "v2HashTypeError", []
                        ret = "v2ZipHashError"
                        if __v2_zipverify(zfile, sigstart, sigend, cdend, filesize, algs_for_zip_dict):
                            ret = "OK"
                            for cert in ver_certs:
                                verify.append(ver_chain)
    return ret, verify

def verifyapk(jarfile):
    verify = []
    if not is_zipfile(jarfile):
        ret = "BadZip"
    else:
        try:
            zfile = ApkFile(jarfile, 'r')
            # print repr(zfile._comment)
            # print zfile._comment.encode("hex")
            # print "21,309,521"
            # print "%08X" % 21309521
            # print "01452851"
            # print "55460506 51284501 00000000000000000000000000000000000000000000"
            # import struct
            # if len(zfile._comment) > 8:
            #     print struct.unpack("L",zfile._comment[0:4])[0]
            #     print struct.unpack("L",zfile._comment[4:8])[0]
            if is_sigv2(zfile):
                ret, verify = verifysigv2(zfile)
            else:
                ret, verify = verifysigv1(zfile)
            zfile.close()
        except Exception,e:
            #import logging
            #logging.exception(e)
            ret = "ZipError"
    #certfile = os.path.join(certdir,"cert.crt")
    #f = open(certfile,"wb")
    #for certname,certcontent in certfiles.items():
    #    f.write(certcontent)
    #    f.write("\r\n")
    #f.close()#
    return ret,verify

if __name__ == "__main__":
    x, y = verifyjar(r"test.zip")
    print x,y
    exit(0)
