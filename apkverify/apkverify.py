#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function, unicode_literals

import binascii
import hashlib
import struct
import math
import sys
import re

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


class ApkSignature:
    def __init__(self, apkpath='test.apk', fd=None):
        self.verified = False
        self.sigv1 = None
        self.__mf_buff = b''
        self.__mf_dict = {}
        self.__files_in_meta_inf = []
        self.sigv2 = None
        self.certs = {}
        self.chains1 = set()
        self.chains2 = set()
        self.errors = []
        self.apkpath = apkpath
        self.zip_file = None
        if fd:
            self.zip_file = ApkFile(fd, 'r')
        else:
            if is_zipfile(self.apkpath):
                self.zip_file = ApkFile(self.apkpath, 'r')
        if self.zip_file is None:
            raise Exception('bad zip')
        # print(repr(zfile._comment))
        # print(zfile._comment.encode('hex'))
        # print('21,309,521')
        # print('%08X' % 21309521)
        # print('01452851')
        # print('55460506 51284501 00000000000000000000000000000000000000000000')
        # import struct
        # if len(zfile._comment) > 8:
        #     print(struct.unpack('<L',zfile._comment[0:4])[0])
        #     print(struct.unpack('<L',zfile._comment[4:8])[0])

    def __del__(self):
        if self.zip_file:
            self.zip_file.close()

    @staticmethod
    def to_bytes(bytes_or_str):
        if not isinstance(bytes_or_str, bytes):
            value = bytes_or_str.encode('utf-8')
        else:
            value = bytes_or_str
        return value  # Instance of bytes

    def is_sigv2(self):
        v2 = False
        try:
            for zipInfo in self.zip_file.infolist():
                # print(repr(zipInfo.comment))
                filename = self.to_bytes(zipInfo.orig_filename)
                #if not isinstance(object2hash, bytes):
                #    object2hash = object2hash.encode('utf-8')

                # if type(filename) is str:
                #     filename_binary = filename
                # elif type(filename) is unicode:
                #     filename_binary = filename.encode('utf8')
                # else:
                #     filename_binary = str(filename)
                if filename.endswith(b'/'):
                    continue
                if filename.startswith(b'META-INF/'):
                    if filename.endswith(b'.SF'):
                        for sf_line in self.zip_file.read(zipInfo).split(b'\n'):
                            if sf_line.startswith(b'X-Android-APK-Signed:'):
                                sf_line = sf_line.split(b':')[1].strip()
                                if sf_line == b'2':
                                    v2 = True
        except Exception as error_message:
            self.errors.append('GlobalZipReadError {}'.format(str(error_message)))

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
            for sig in self.__files_in_meta_inf:
                if sig.endswith('.DSA') or sig.endswith('.RSA') or sig.endswith('.EC'):
                    sigv1sigs.append(sig)
            if len(sigv1sigs) == 0:
                self.errors.append('Sigv1SigFileLost')
                return self.sigv1
            sigv1sfs = {}
            for sig in sigv1sigs:
                sfbuf = self.__v1_jarverifysigfile(sig)
                if sfbuf:
                    sigv1sfs[sig] = sfbuf
            if len(sigv1sfs) == 0:
                self.errors.append('Sigv1SfFileError')
                return self.sigv1
            sigv1verifys = []
            for sig, sfbuf in sigv1sfs.items():
                sigbuf = self.zip_file.read(sig)
                ver_chains, all_apk_certs = check_sig_pkcs7(sigbuf, sfbuf)
                self.certs.update(all_apk_certs)
                if len(ver_chains) > 0:
                    self.sigv1 = True
                    sigv1verifys.append(sig)
                    for chain in ver_chains:
                        self.chains1.add(tuple(chain))
            if len(sigv1verifys) == 0:
                self.errors.append('Sigv1CertVerifyFailed')
                return self.sigv1
        return self.sigv1

    def __verify_sigv2(self):
        if self.sigv2 is not None:
            return self.sigv2
        self.sigv2 = False
        sig, sig_start, sig_end, cd_end, filesize = self.__v2_zipfindsig()
        # print(sig)
        if 0x7109871a not in sig:
            self.errors.append('Sigv2SigPartLost')
            return self.sigv2
        else:
            sigv2_sigs = []
            sigv2_certs = []
            # not used? sigv2_hashs = []
            sigv2_verifys = []
            for signers in self.extract_list_by_int_prefix(sig.get(0x7109871a)):
                for signer in self.extract_list_by_int_prefix(signers):
                    # f = open('debug-xxx.txt','wb')
                    # f.write(signer)
                    # f.close()
                    data = self.extract_list_by_int_prefix(signer)
                    if len(data) >= 3:
                        signed_data, signatures, public_key_bytes = data[:3]
                        sigv2_sigs.append(data)
                        algs_for_zip, ver_chains, all_apk_certs = check_sig_v2(signed_data, signatures, public_key_bytes)
                        self.certs.update(all_apk_certs)
                        if len(ver_chains) > 0:
                            sigv2_certs.append(ver_chains)
                            algs_for_zip_dict = {}
                            for _hash_type_tuple_, hash_value in algs_for_zip:
                                (hash_type, _) = _hash_type_tuple_
                                if hash_type not in algs_for_zip_dict:
                                    algs_for_zip_dict[hash_type] = hash_value
                                else:
                                    if algs_for_zip_dict[hash_type] != hash_value:
                                        self.errors.append('Sigv2HashTypeError')
                                        return self.sigv2
                            if self.__v2_zipverify(sig_start, sig_end, cd_end, filesize, algs_for_zip_dict):
                                sigv2_verifys.append(ver_chains)
                                for chain in ver_chains:
                                    self.chains2.add(tuple(chain))
                                    self.sigv2 = True
            if len(sigv2_verifys) == 0:
                self.errors.append('Sigv2SigBuffError')
            else:
                if len(sigv2_certs) == 0:
                    self.errors.append('Sigv2CertVerifyFailed')
                else:
                    if len(sigv2_verifys) == 0:
                        self.errors.append('Sigv2ZipHashError')
        return self.sigv2

    def all_certs(self, readable=False):
        """
        :param readable:
        :param readable: PEM or Readable Tuple
        :return:
        """
        ret = []
        for k, v in self.certs.items():
            if readable:
                ret.append(v[:3])
            else:
                ret.append(v[3])
        return ret

    def get_certs(self, version=-1, readable=False, include_on_chain=False):
        """
        :param version:
        :param readable: PEM or Readable Tuple
        :param include_on_chain: include ALL cert on chain (from chain head to ROOT CA, all of them)
        :return:
        """
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
        """
        :param version:
        :param readable: PEM or Readable Tuple
        :return:
        """
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

    def __get_chains(self, version=-1):
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
        # print(repr(buf))
        mf_dict = {}
        # idx = buf.find('\r\n\r\n')
        # if idx > 0:
        #     s = '\r\n'
        # else:
        #     s = '\n'
        # bl = buf.split(s * 2)
        bl = re.split(b'(\r\n\r\n|\n\n)', __sf_buff)
        bx = []
        for i in range(0, int(math.ceil(len(bl) * 1.0 / 2))):
            bx.append(b''.join(bl[i * 2:i * 2 + 2]))
        # bl = re.split('\n\n', buf)
        # bl = re.findall(r'(\n\r\n|\n\n)(.*)(\n\r\n|\n\n)', buf, re.MULTILINE)
        # print(bl)
        # for b1 in bl:
        for b1 in bx:
            # print(repr(b1))
            # bs = b1.strip()
            # if len(bs) > 0:
            if b1.strip():
                d = dict(map(
                    lambda z: (z[0], z[1]), filter(
                        lambda y: len(y) == 2, map(
                            lambda x: x.split(b': ', 1), re.split(b'(\r?\n)\\b',
                                                                  re.sub(b'(\r|)\n ', b'', b1))
                        )
                    )
                ))
                # print(d)
                # d = dict(map(lambda z: (z[0], z[1]),
                #              filter(lambda y: len(y) == 2,
                #                     map(lambda x: x.split(': ', 1),
                #                         bs.replace(s + ' ', '').split(s)))))
                if b'Name' in d:
                    k = d[b'Name']
                elif b'Signature-Version' in d:
                    k = b'META-INF/MANIFEST.MF'
                elif b'Manifest-Version' in d:
                    k = None
                else:
                    k = None
                if k:
                    d[b'buf'] = b1
                    d[b'buf2'] = re.sub(b'(\r|)\n ', b'', b1)
                    # d['buf'] = b1 + s * 2
                    # d['buf2'] = b1.replace(s + ' ', '') + s * 2
                    if k not in mf_dict:
                        mf_dict[k] = d
                    else:
                        # print(k)
                        raise Exception(u'dup in manifest.mf')
        return mf_dict

    @classmethod
    def __v1_hash_digest_verify(cls, attributes_attributes, string_entry, byte_data):
        failed = 0
        verify = 0
        for k, v in attributes_attributes.items():
            if k.endswith(string_entry):
                x = k[:-len(string_entry)].upper()
                h = binascii.a2b_base64(v)
                if x == b'SHA-512':
                    if hashlib.sha512(byte_data).digest() == h:
                        verify += 1
                    else:
                        failed += 1
                elif x == b'SHA-384':
                    if hashlib.sha384(byte_data).digest() == h:
                        verify += 1
                    else:
                        failed += 1
                elif x == b'SHA-256':
                    if hashlib.sha256(byte_data).digest() == h:
                        verify += 1
                    else:
                        failed += 1
                elif x == b'SHA1':
                    if hashlib.sha1(byte_data).digest() == h:
                        verify += 1
                    else:
                        failed += 1
                else:
                    pass  # return None
        if failed:
            return False
        elif verify:
            return True
        else:
            return None

    def __v1_jarverifymanifest(self):
        dupfile_in_bytes = {}
        try:
            self.__mf_buff = self.zip_file.read('META-INF/MANIFEST.MF')
            self.__mf_dict = self.__v1_jarmf2dict(self.__mf_buff)
        except Exception as error_message:
            # logging.exception(e)
            self.errors.append('Sigv1MfFileError with {}'.format(str(error_message)))
            return False
        for zipInfo in self.zip_file.infolist():
            # print(repr(zipInfo.comment))
            filename = zipInfo.orig_filename
            if filename.endswith('/'):
                continue
            if filename.startswith('META-INF/'):
                self.__files_in_meta_inf.append(filename)
                continue
            if type(filename) is unicode_cls:
                filename_binary = filename.encode('utf8')
            else:
                filename_binary = str(filename)
            if filename_binary not in dupfile_in_bytes:
                dupfile_in_bytes[filename_binary] = 1
            else:
                dupfile_in_bytes[filename_binary] += 1
                self.errors.append('GlobalZipDupEntry %s' % filename)
                return False
            mf_data = self.__mf_dict.get(filename_binary)
            if mf_data:
                buf = self.zip_file.read(zipInfo)
                vok = self.__v1_hash_digest_verify(mf_data, b'-Digest', buf)
                if vok is None:
                    self.errors.append('Sigv1HashTypeError %s' % filename)
                    return False
                elif vok is False:
                    self.errors.append('Sigv1HashFileFailed %s' % filename)
                    return False
                else:
                    pass  # True
            else:
                # print(mf_dict)
                self.errors.append('Sigv1HashFileLost %s' % filename)
                # 0 byte filehash lost in manifest.mf is OK
                if zipInfo.file_size > 0:
                    return False
        lost_file_in_bytes = list(set(self.__mf_dict.keys()).difference(set(dupfile_in_bytes.keys())))
        if len(lost_file_in_bytes) > 0:
            lost_dexs = 0
            lost_other = 0
            lost_meta = 0
            for filename_binary in lost_file_in_bytes:
                if b'/' not in filename_binary and filename_binary.startswith(b'classes') and filename_binary.endswith(
                        b'.dex'):
                    lost_dexs += 1
                elif filename_binary.startswith(b'META-INF/'):
                    lost_meta += 1
                else:
                    lost_other += 1
            if lost_other > 0:
                self.errors.append('Sigv1SomeFileLost %d' % (lost_other + lost_dexs,))
                return False
            elif lost_dexs > 0:
                self.errors.append('Sigv1ClassDexLost %d' % (lost_dexs,))
                return False
        return True

    def __v1_jarverifysigfile(self, sigfile):
        try:
            sf_buf = self.zip_file.read(sigfile.rsplit('.', 1)[0] + '.SF')
            sf_dic = self.__v1_jarmf2dict(sf_buf)
        except Exception as error_message:
            # logging.exception(e)
            self.errors.append('Sigv1SfFileError {}'.format(str(error_message)))
            return False
        mfv = sf_dic.pop(b'META-INF/MANIFEST.MF', {})
        # ignore   '-Digest-Manifest-Main-Attributes'
        vok = self.__v1_hash_digest_verify(mfv, b'-Digest-Manifest', self.__mf_buff)
        if vok is None:
            vok = self.__v1_hash_digest_verify(mfv, b'-Digest-Manifest-Main-Attributes', self.__mf_buff)
        if vok is True:
            # 事实证明，这是个或选项。java(SignatureFileVerifier.java), android(JarVerifier.java) 都是
            return sf_buf
        elif vok is False:
            pass  # 不再驗證不必要的 SHA1-Digest-Manifest-Main-Attributes 與 SHA1-Digest-Manifest 了
            # return 'SFMFFileHashError',''
        else:
            pass  # 這個貌似不是必要選項
            # return 'SFMFHashTypeError',''
        for sfk, sfv in sf_dic.items():
            if sfk.startswith(b'META-INF/'):
                pass
            elif sfk in self.__mf_dict:
                buff = self.__mf_dict[sfk][b'buf']
                buf2 = self.__mf_dict[sfk][b'buf2']
                digest_suffix = b'-Digest'
                vok = self.__v1_hash_digest_verify(sfv, b'-Digest', buff)
                if vok is None:
                    digest_suffix = b'-Digest-Manifest'
                    vok = self.__v1_hash_digest_verify(sfv, b'-Digest-Manifest', buff)
                if vok is None:
                    self.errors.append('Sigv1HashLineError')
                    return False
                elif vok is False:
                    vok = self.__v1_hash_digest_verify(sfv, digest_suffix, buf2)
                    if vok is False:
                        # print(sfv)
                        # print(repr(buf2))
                        self.errors.append('Sigv1HashLineFailed')
                        return False
                    else:
                        pass  # None True
                else:
                    pass  # True
            else:
                self.errors.append('Sigv1HashLineLost')
                return False
        lost_line = list(set(self.__mf_dict.keys()).difference(set(sf_dic.keys())))
        if len(lost_line) > 0:
            lost_other = 0
            lost_meta = 0
            for filename_binary in lost_line:
                if filename_binary.startswith('META-INF/'):
                    lost_meta += 1
                else:
                    lost_other += 1
            if lost_other > 0:
                self.errors.append('Sigv1SomeLineLost')
                return False
            else:
                pass
        return sf_buf

    def __v2_zipfindsig(self):
        ret_sig_start = -1
        ret_offset_cd = -1
        ret_cd_end = -1
        filesize = -1
        apk_sig_block_min_size = 32
        ret_v2sigs = {}
        break_goto_fail = True
        while break_goto_fail:
            break_goto_fail = False
            endrec = _EndRecData(self.zip_file.fp)
            size_cd = endrec[_ECD_SIZE]  # bytes in central directory
            offset_cd = endrec[_ECD_OFFSET]  # offset of central directory
            if offset_cd < apk_sig_block_min_size:
                break
            self.zip_file.fp.seek(0, 2)
            filesize = self.zip_file.fp.tell()
            if offset_cd + size_cd > filesize:
                break
            ret_offset_cd = offset_cd
            ret_cd_end = offset_cd + size_cd
            self.zip_file.fp.seek(offset_cd - 24)
            buf = self.zip_file.fp.read(24)
            if buf[8:] != b'APK Sig Block 42':
                break
            sigin_foot = struct.unpack('<Q', buf[:8])[0]
            if sigin_foot < 24 or sigin_foot > filesize:
                break
            ret_sig_start = offset_cd - sigin_foot - 8
            if ret_sig_start < 0 or ret_sig_start > filesize:
                break
            self.zip_file.fp.seek(ret_sig_start)
            buf = self.zip_file.fp.read(sigin_foot + 8)
            sigin_head = struct.unpack('<Q', buf[:8])[0]
            if sigin_foot != sigin_head:
                break
            idx = 8
            while idx + 12 <= sigin_head - 24:
                length = struct.unpack('<Q', buf[idx:idx + 8])[0]
                index = struct.unpack('<L', buf[idx + 8:idx + 12])[0]
                s = buf[idx + 12:idx + 12 + length - 4]
                ret_v2sigs[index] = s
                idx += 12
                idx += length - 4
                # buff2 = buf[idx:]
                # print(repr(buff2))
            # print(v2sig)
        return ret_v2sigs, ret_sig_start, ret_offset_cd, ret_cd_end, filesize

    @classmethod
    def extract_list_by_int_prefix(cls, data):
        datas = []
        idx = 0
        while idx + 4 <= len(data):
            i = struct.unpack('<L', data[idx:idx + 4])[0]
            s = data[idx + 4:idx + 4 + i]
            idx += 4 + i
            datas.append(s)
            # print('debug', idx, len(data))
            # buff2 = sig[idx:]
            # print(repr(buff2))
        if idx != len(data):
            print('warn', idx, len(data))
        return datas

    def __v2_zipverify(self, sig_start, sig_end, cd_end, filesize, algs_for_zip_dict):
        buffer_size = 1024 * 1024
        hash_types = {}
        hash_values = {}
        if algs_for_zip_dict:
            for hash_type, hash_value in algs_for_zip_dict.items():
                # print(hash_type,binascii.b2a_hex(hash_value))
                if hash_type == 'SHA256':
                    hash_types[hash_type] = hashlib.sha256
                    hash_values[hash_type] = []
                elif hash_type == 'SHA512':
                    hash_types[hash_type] = hashlib.sha512
                    hash_values[hash_type] = []
                else:
                    return False
            rl = [(0, sig_start), (sig_end, cd_end)]  # , (cd_end, filesize)]
            for _seek, _end in rl:
                self.zip_file.fp.seek(_seek)
                while _seek < _end:
                    _read = min(buffer_size, _end - _seek)
                    _buff = b'\xa5' + struct.pack('<L', _read) + self.zip_file.fp.read(_read)
                    for hash_type in algs_for_zip_dict.keys():
                        hb = hash_types[hash_type](_buff).digest()
                        hash_values[hash_type].append(hb)
                        # print(_seek,_read,binascii.b2a_hex(hb))
                    _seek += _read
            _seek, _end = cd_end, filesize
            self.zip_file.fp.seek(_seek)
            _eocd = self.zip_file.fp.read()
            # _old_off = _eocd[16:16+4]
            _new_off = struct.pack('<L', sig_start)
            # print('xxxxxxx',binascii.b2a_hex(_old_off))
            # print('xxxxxxx',binascii.b2a_hex(struct.pack('<L',sig_start)))
            # print('xxxxxxx',binascii.b2a_hex(struct.pack('<L',sig_end)))
            _eocd = _eocd[:16] + _new_off + _eocd[16 + 4:]
            _seek, _end = 0, len(_eocd)
            while _seek < _end:
                _read = min(buffer_size, _end - _seek)
                _buff = b'\xa5' + struct.pack('<L', _read) + _eocd[_seek:_seek + _read]
                for hash_type in algs_for_zip_dict.keys():
                    hb = hash_types[hash_type](_buff).digest()
                    hash_values[hash_type].append(hb)
                    # print(_seek,_read,binascii.b2a_hex(hb))
                _seek += _read
            for hash_type, hash_value in algs_for_zip_dict.items():
                _buff = b'\x5a' + struct.pack('<L', len(hash_values[hash_type])) + b''.join(hash_values[hash_type])
                hh = hash_types[hash_type](_buff).digest()
                if hh != hash_value:
                    return False
            return True
        return False
