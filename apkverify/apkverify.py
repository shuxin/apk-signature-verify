#!/usr/bin/python
# coding=utf-8

import binascii
import hashlib
import logging
import struct
import math
import sys
import re
import os

ApkFile = None
if sys.version_info < (3,):
    try:
        # this_is_a__robust_version_zipfile__for__zip_with_password__or__zip_with_bad_data
        from .apkfile import is_zipfile, _EndRecData, _ECD_SIZE, _ECD_OFFSET
        from .apkfile import ApkFile
    except ImportError as e:
        pass
if ApkFile is None:
    from zipfile import is_zipfile, _EndRecData, _ECD_SIZE, _ECD_OFFSET
    from zipfile import ZipFile as ApkFile
from .sigverify import check_sig_pkcs7, check_sig_v2

if sys.version_info < (3,):
    unicode_cls = unicode
    byte_cls = str
    int_types = (int, long)
    basestring_cls = (unicode, str)
else:
    unicode_cls = str
    byte_cls = bytes
    int_types = (int,)
    basestring_cls = (str, bytes)

DEBUG = True


class ApkSignature():
    def __init__(self, apkpath=u"test.apk",fd=None):
        self.verified = False
        self.sigv1 = None
        self.__mf_buff = b""
        self.__mf_dict = {}
        self.__files_in_metainf = []
        self.sigv2 = None
        self.certs = {}
        self.chains1 = set()
        self.chains2 = set()
        self.errors = []
        self.apkpath = apkpath
        self.zfile = None
        if fd:
            self.zfile = ApkFile(fd, 'r')
        else:
            if is_zipfile(self.apkpath):
                self.zfile = ApkFile(self.apkpath, 'r')
        if self.zfile is None:
            raise Exception(u"bad zip")
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

    def __del__(self):
        if self.zfile:
            self.zfile.close()

    def is_sigv2(self):
        v2 = False
        try:
            for zipInfo in self.zfile.infolist():
                # print repr(zipInfo.comment)
                filename = zipInfo.orig_filename
                # if type(filename) is str:
                #     filename_binary = filename
                # elif type(filename) is unicode:
                #     filename_binary = filename.encode("utf8")
                # else:
                #     filename_binary = str(filename)
                if filename.endswith(u"/"):
                    continue
                if filename.startswith(u"META-INF/"):
                    if filename.endswith(u".SF"):
                        for line in self.zfile.read(zipInfo).split(b"\n"):
                            if line.startswith(b"X-Android-APK-Signed:"):
                                line = line.split(b":")[1].strip()
                                if line == b'2':
                                    v2 = True
        except Exception as e:
            self.errors.append("GlobalZipReadError")
        return v2

    def verify(self, version=-1):
        if version == 1:
            return self.__verify_sigv1()
        elif version == 2:
            return self.__verify_sigv2()
        else:
            # auto
            if self.is_sigv2():
                return self.__verify_sigv2()
            else:
                return self.__verify_sigv1()

    def __verify_sigv1(self):
        if self.sigv1 is not None:
            return self.sigv1
        self.sigv1 = False
        if self.__v1_jarverifymanifest():
            sigv1sigs = []
            for sig in self.__files_in_metainf:
                if sig.endswith(".DSA") or sig.endswith(".RSA") or sig.endswith(".EC"):
                    sigv1sigs.append(sig)
            if len(sigv1sigs) == 0:
                self.errors.append("Sigv1SigFileLost")
                return self.sigv1
            sigv1sfs = {}
            for sig in sigv1sigs:
                sfbuf = self.__v1_jarverifysigfile(sig)
                if sfbuf:
                    sigv1sfs[sig] = sfbuf
            if len(sigv1sfs) == 0:
                self.errors.append("Sigv1SfFileError")
                return self.sigv1
            sigv1verifys = []
            for sig, sfbuf in sigv1sfs.items():
                sigbuf = self.zfile.read(sig)
                ver_chains, all_certs = check_sig_pkcs7(sigbuf, sfbuf)
                self.certs.update(all_certs)
                if len(ver_chains) > 0:
                    self.sigv1 = True
                    sigv1verifys.append(sig)
                    for chain in ver_chains:
                        self.chains1.add(tuple(chain))
            if len(sigv1verifys) == 0:
                self.errors.append("Sigv1CertVerifyFailed")
                return self.sigv1
        return self.sigv1

    def __verify_sigv2(self):
        if self.sigv2 is not None:
            return self.sigv2
        self.sigv2 = False
        verify = []
        sig, sigstart, sigend, cdend, filesize = self.__v2_zipfindsig()
        # print sig
        if not 0x7109871a in sig:
            self.errors.append("Sigv2SigPartLost")
            return self.sigv2
        else:
            sigv2sigs = []
            sigv2certs = []
            sigv2hashs = []
            sigv2verifys = []
            for signers in self.extract_list_by_int_prefix(sig.get(0x7109871a)):
                for signer in self.extract_list_by_int_prefix(signers):
                    # f = open("debug-xxx.txt","wb")
                    # f.write(signer)
                    # f.close()
                    data = self.extract_list_by_int_prefix(signer)
                    if len(data) >= 3:
                        signedData, signatures, publicKeyBytes = data[:3]
                        sigv2sigs.append(data)
                        algs_for_zip, ver_chains, all_certs = check_sig_v2(signedData, signatures, publicKeyBytes)
                        self.certs.update(all_certs)
                        if len(ver_chains) > 0:
                            sigv2certs.append(ver_chains)
                            algs_for_zip_dict = {}
                            for _hashtype_tuple_, hashvalue in algs_for_zip:
                                (hashtype, _) = _hashtype_tuple_
                                if not hashtype in algs_for_zip_dict:
                                    algs_for_zip_dict[hashtype] = hashvalue
                                else:
                                    if algs_for_zip_dict[hashtype] != hashvalue:
                                        self.errors.append("Sigv2HashTypeError")
                                        return self.sigv2
                            if self.__v2_zipverify(sigstart, sigend, cdend, filesize, algs_for_zip_dict):
                                sigv2verifys.append(ver_chains)
                                for chain in ver_chains:
                                    self.chains2.add(tuple(chain))
                                    self.sigv2 = True
            if len(sigv2verifys) == 0:
                self.errors.append("Sigv2SigBuffError")
            else:
                if len(sigv2certs) == 0:
                    self.errors.append("Sigv2CertVerifyFailed")
                else:
                    if len(sigv2verifys) == 0:
                        self.errors.append("Sigv2ZipHashError")
        return self.sigv2

    def all_certs(self, readable=False):
        '''
        :param pem: PEM or Readable Tuple
        :return:
        '''
        ret = []
        for k, v in self.certs.items():
            if readable:
                ret.append(v[:3])
            else:
                ret.append(v[3])
        return ret

    def get_certs(self, version=-1, readable=False, include_on_chain=False):
        '''
        :param pem: PEM or Readable Tuple
        :param include_on_chain: include ALL cert on chain (from chain head to ROOT CA, all of them)
        :return:
        '''
        ret = []
        for one_chain in self.__get_chains(version):
            for crt in one_chain:
                v = self.certs.get(crt)
                if readable:
                    ret.append(v[:3])
                else:
                    ret.append(v[3])
                if not include_on_chain:
                    break
        return ret

    def get_chains(self, version=-1, readable=False):
        '''
        :param pem: PEM or Readable Tuple
        :return:
        '''
        ret = []
        for one_chain in self.__get_chains(version):
            ret_chain = []
            for crt in one_chain:
                v = self.certs.get(crt)
                if readable:
                    ret_chain.append(v[:3])
                else:
                    ret_chain.append(v[3])
            ret.append(ret_chain)
        return ret

    def __get_chains(self,version=-1):
        chains = []
        if version == 1:
            chains.extend(self.chains1)
        elif version == 2:
            chains.extend(self.chains2)
        else:
            chains.extend(self.chains1)
            chains.extend(self.chains2)
        return chains

    @classmethod
    def __v1_jarmf2dict(cls, __sf_buff):
        # print repr(buf)
        mf_dict = {}
        # idx = buf.find("\r\n\r\n")
        # if idx > 0:
        #     s = "\r\n"
        # else:
        #     s = "\n"
        # bl = buf.split(s * 2)
        bl = re.split(b'(\r\n\r\n|\n\n)', __sf_buff)
        bx = []
        for i in range(0, int(math.ceil(len(bl) * 1.0 / 2))):
            bx.append(b"".join(bl[i * 2:i * 2 + 2]))
        # bl = re.split('\n\n', buf)
        # bl = re.findall(r"(\n\r\n|\n\n)(.*)(\n\r\n|\n\n)", buf, re.MULTILINE)
        # print bl
        # for b1 in bl:
        for b1 in bx:
            # print repr(b1)
            # bs = b1.strip()
            # if len(bs) > 0:
            if b1.strip():
                d = dict(map(
                    lambda z: (z[0], z[1]), filter(
                        lambda y: len(y) == 2,map(
                            lambda x: x.split(b": ", 1),re.split(b"(\r?\n)\\b",re.sub(b"(\r|)\n ", b"", b1))
                        )
                    )
                ))
                # print d
                # d = dict(map(lambda z: (z[0], z[1]), filter(lambda y: len(y) == 2, map(lambda x: x.split(": ", 1), bs.replace(s + " ", "").split(s)))))
                if b"Name" in d:
                    k = d[b"Name"]
                elif b"Signature-Version" in d:
                    k = b"META-INF/MANIFEST.MF"
                elif b"Manifest-Version" in d:
                    k = None
                else:
                    k = None
                if k:
                    d[b"buf"] = b1
                    d[b"buf2"] = re.sub(b"(\r|)\n ", b"", b1)
                    # d["buf"] = b1 + s * 2
                    # d["buf2"] = b1.replace(s + " ", "") + s * 2
                    if not k in mf_dict:
                        mf_dict[k] = d
                    else:
                        # print k
                        raise Exception(u"dup in manifest.mf")
        return mf_dict

    @classmethod
    def __v1_hash_digest_verify(cls, Attributes_attributes, String_entry, byte_data):
        Failed = 0
        Verify = 0
        for k, v in Attributes_attributes.items():
            if k.endswith(String_entry):
                x = k[:-len(String_entry)].upper()
                h = binascii.a2b_base64(v)
                if x == b"SHA-512":
                    if hashlib.sha512(byte_data).digest() == h:
                        Verify += 1
                    else:
                        Failed += 1
                elif x == b"SHA-384":
                    if hashlib.sha384(byte_data).digest() == h:
                        Verify += 1
                    else:
                        Failed += 1
                elif x == b"SHA-256":
                    if hashlib.sha256(byte_data).digest() == h:
                        Verify += 1
                    else:
                        Failed += 1
                elif x == b"SHA1":
                    if hashlib.sha1(byte_data).digest() == h:
                        Verify += 1
                    else:
                        Failed += 1
                else:
                    pass#return None
        if Failed:
            return False
        elif Verify:
            return True
        else:
            return None

    def __v1_jarverifymanifest(self):
        dupfile_in_bytes = {}
        try:
            self.__mf_buff = self.zfile.read(u"META-INF/MANIFEST.MF")
            self.__mf_dict = self.__v1_jarmf2dict(self.__mf_buff)
        except Exception as e:
            # logging.exception(e)
            self.errors.append(u"Sigv1MfFileError")
            return False
        for zipInfo in self.zfile.infolist():
            # print repr(zipInfo.comment)
            filename = zipInfo.orig_filename
            if filename.endswith(u"/"):
                continue
            if filename.startswith(u"META-INF/"):
                self.__files_in_metainf.append(filename)
                continue
            if type(filename) is unicode_cls:
                filename_binary = filename.encode("utf8")
            else:
                filename_binary = str(filename)
            if not filename_binary in dupfile_in_bytes:
                dupfile_in_bytes[filename_binary] = 1
            else:
                dupfile_in_bytes[filename_binary] += 1
                self.errors.append(u"GlobalZipDupEntry %s" % filename)
                return False
            mf_data = self.__mf_dict.get(filename_binary)
            if mf_data:
                buf = self.zfile.read(zipInfo)
                vok = self.__v1_hash_digest_verify(mf_data, b"-Digest", buf)
                if vok is None:
                    self.errors.append("Sigv1HashTypeError %s" % filename)
                    return False
                elif vok == False:
                    self.errors.append("Sigv1HashFileFailed %s" % filename)
                    return False
                else:
                    pass  # True
            else:
                # print mf_dict
                self.errors.append("Sigv1HashFileLost %s" % filename)
                # 0 byte filehash lost in manifest.mf is OK
                if zipInfo.file_size > 0:
                    return False
        lostfile_in_bytes = list(set(self.__mf_dict.keys()).difference(set(dupfile_in_bytes.keys())))
        if len(lostfile_in_bytes) > 0:
            lostdexs = 0
            lostother = 0
            lostmeta = 0
            for filename_binary in lostfile_in_bytes:
                if b"/" not in filename_binary and filename_binary.startswith(b"classes") and filename_binary.endswith(
                        b".dex"):
                    lostdexs += 1
                elif filename_binary.startswith(b'META-INF/'):
                    lostmeta += 1
                else:
                    lostother += 1
            if lostother > 0:
                self.errors.append(u"Sigv1SomeFileLost %d" % (lostother + lostdexs,))
                return False
            elif lostdexs > 0:
                self.errors.append(u"Sigv1ClassDexLost %d" % (lostdexs,))
                return False
        return True

    def __v1_jarverifysigfile(self, sigfile):
        try:
            sf_buf = self.zfile.read(sigfile.rsplit(".", 1)[0] + ".SF")
            sf_dic = self.__v1_jarmf2dict(sf_buf)
        except Exception as e:
            # logging.exception(e)
            self.errors.append(u"Sigv1SfFileError")
            return False
        mfv = sf_dic.pop(b"META-INF/MANIFEST.MF", {})
        # ignore   "-Digest-Manifest-Main-Attributes"
        vok = self.__v1_hash_digest_verify(mfv, b"-Digest-Manifest", self.__mf_buff)
        if vok is None:
            vok = self.__v1_hash_digest_verify(mfv, b"-Digest-Manifest-Main-Attributes", self.__mf_buff)
        if vok is True:
            # 事实证明，这是个或选项。java(SignatureFileVerifier.java), android(JarVerifier.java) 都是
            return sf_buf
        elif vok is False:
            pass  # 不再驗證不必要的 SHA1-Digest-Manifest-Main-Attributes 與 SHA1-Digest-Manifest 了
            # return "SFMFFileHashError",""
        else:
            pass  # 這個貌似不是必要選項
            # return "SFMFHashTypeError",""
        for sfk, sfv in sf_dic.items():
            if sfk.startswith(b"META-INF/"):
                pass
            elif sfk in self.__mf_dict:
                buff = self.__mf_dict[sfk][b"buf"]
                buf2 = self.__mf_dict[sfk][b"buf2"]
                digest_suffix = b"-Digest"
                vok = self.__v1_hash_digest_verify(sfv, b"-Digest", buff)
                if vok is None:
                    digest_suffix = b"-Digest-Manifest"
                    vok = self.__v1_hash_digest_verify(sfv, b"-Digest-Manifest", buff)
                if vok is None:
                    self.errors.append(u"Sigv1HashLineError")
                    return False
                elif vok == False:
                    vok = self.__v1_hash_digest_verify(sfv, digest_suffix, buf2)
                    if vok == False:
                        # print sfv
                        # print repr(buf2)
                        self.errors.append(u"Sigv1HashLineFailed")
                        return False
                    else:
                        pass  # None True
                else:
                    pass  # True
            else:
                self.errors.append(u"Sigv1HashLineLost")
                return False
        lostline = list(set(self.__mf_dict.keys()).difference(set(sf_dic.keys())))
        if len(lostline) > 0:
            lostother = 0
            lostmeta = 0
            for filename_binary in lostline:
                if filename_binary.startswith('META-INF/'):
                    lostmeta += 1
                else:
                    lostother += 1
            if lostother > 0:
                self.errors.append(u"Sigv1SomeLineLost")
                return False
            else:
                pass
        return sf_buf

    def __v2_zipfindsig(self):
        ret_sig_start = -1
        ret_offset_cd = -1
        ret_cd_end = -1
        filesize = -1
        APK_SIG_BLOCK_MIN_SIZE = 32
        ret_v2sigs = {}
        breakgotofail = True
        while breakgotofail:
            breakgotofail = False
            endrec = _EndRecData(self.zfile.fp)
            size_cd = endrec[_ECD_SIZE]  # bytes in central directory
            offset_cd = endrec[_ECD_OFFSET]  # offset of central directory
            if (offset_cd < APK_SIG_BLOCK_MIN_SIZE):
                break
            self.zfile.fp.seek(0, 2)
            filesize = self.zfile.fp.tell()
            if offset_cd + size_cd > filesize:
                break
            ret_offset_cd = offset_cd
            ret_cd_end = offset_cd + size_cd
            self.zfile.fp.seek(offset_cd - 24)
            buf = self.zfile.fp.read(24)
            if buf[8:] != b'APK Sig Block 42':
                break
            siginfoot = struct.unpack("Q", buf[:8])[0]
            if siginfoot < 24 or siginfoot > filesize:
                break
            ret_sig_start = offset_cd - siginfoot - 8
            if ret_sig_start < 0 or ret_sig_start > filesize:
                break
            self.zfile.fp.seek(ret_sig_start)
            buf = self.zfile.fp.read(siginfoot + 8)
            siginhead = struct.unpack("Q", buf[:8])[0]
            if siginfoot != siginhead:
                break
            idx = 8
            while idx + 12 <= siginhead - 24:
                l = struct.unpack("Q", buf[idx:idx + 8])[0]
                i = struct.unpack("L", buf[idx + 8:idx + 12])[0]
                s = buf[idx + 12:idx + 12 + l - 4]
                ret_v2sigs[i] = s
                idx += 12
                idx += l - 4
                # buff2 = buf[idx:]
                # print repr(buff2)
            # print v2sig
        return ret_v2sigs, ret_sig_start, ret_offset_cd, ret_cd_end, filesize

    @classmethod
    def extract_list_by_int_prefix(cls, data):
        datas = []
        idx = 0
        while idx + 4 <= len(data):
            i = struct.unpack("L", data[idx:idx + 4])[0]
            s = data[idx + 4:idx + 4 + i]
            idx += 4 + i
            datas.append(s)
            # print "debug",idx,len(data)
            # buff2 = sig[idx:]
            # print repr(buff2)
        if idx != len(data):
            print("warn", idx, len(data))
        return datas

    def __v2_zipverify(self, sigstart, sigend, cdend, filesize, algs_for_zip_dict):
        READ = 1024 * 1024
        hashtypes = {}
        hashvalues = {}
        if algs_for_zip_dict:
            for hashtype, hashvalue in algs_for_zip_dict.items():
                # print hashtype,binascii.b2a_hex(hashvalue)
                if hashtype == u"SHA256":
                    hashtypes[hashtype] = hashlib.sha256
                    hashvalues[hashtype] = []
                elif hashtype == u"SHA512":
                    hashtypes[hashtype] = hashlib.sha512
                    hashvalues[hashtype] = []
                else:
                    return False
            rl = [(0, sigstart), (sigend, cdend)]  # , (cdend, filesize)]
            for _seek, _end in rl:
                self.zfile.fp.seek(_seek)
                while _seek < _end:
                    _read = min(READ, _end - _seek)
                    _buff = b'\xa5' + struct.pack("L", _read) + self.zfile.fp.read(_read)
                    for hashtype in algs_for_zip_dict.keys():
                        hb = hashtypes[hashtype](_buff).digest()
                        hashvalues[hashtype].append(hb)
                        # print _seek,_read,binascii.b2a_hex(hb)
                    _seek += _read
            _seek, _end = cdend, filesize
            self.zfile.fp.seek(_seek)
            _eocd = self.zfile.fp.read()
            # _old_off = _eocd[16:16+4]
            _new_off = struct.pack("L", sigstart)
            # print "xxxxxxx",binascii.b2a_hex(_old_off)
            # print "xxxxxxx",binascii.b2a_hex(struct.pack("L",sigstart))
            # print "xxxxxxx",binascii.b2a_hex(struct.pack("L",sigend))
            _eocd = _eocd[:16] + _new_off + _eocd[16 + 4:]
            _seek, _end = 0, len(_eocd)
            while _seek < _end:
                _read = min(READ, _end - _seek)
                _buff = b'\xa5' + struct.pack("L", _read) + _eocd[_seek:_seek + _read]
                for hashtype in algs_for_zip_dict.keys():
                    hb = hashtypes[hashtype](_buff).digest()
                    hashvalues[hashtype].append(hb)
                    # print _seek,_read,binascii.b2a_hex(hb)
                _seek += _read
            for hashtype, hashvalue in algs_for_zip_dict.items():
                _buff = b'\x5a' + struct.pack("L", len(hashvalues[hashtype])) + b"".join(hashvalues[hashtype])
                hh = hashtypes[hashtype](_buff).digest()
                if hh != hashvalue:
                    return False
            return True
        return False


if __name__ == "__main__":
    a = ApkSignature(os.path.abspath(r"test2.zip"))
    print(a.apkpath)
    sigver = a.is_sigv2()
    v_auto = a.verify()  # auto check version
    v_ver1 = a.verify(1)  # force check version 1
    v_ver2 = a.verify(2)  # force check version 2
    print("Verify:", sigver, v_auto, v_ver1, v_ver2)
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
    exit(0)
