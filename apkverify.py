#!/usr/bin/python
# coding=utf-8

from pkcs7verify import check_sig
from zipfile import is_zipfile, ZipFile
from zipfile import ZipInfo, ZipExtFile
from zipfile import sizeFileHeader, structFileHeader, BadZipfile, stringFileHeader
from zipfile import _FH_SIGNATURE, _FH_FILENAME_LENGTH, _FH_EXTRA_FIELD_LENGTH
import hashlib, base64, os


class ApkInfo (ZipInfo):
    def _decodeExtra(self):
        # Try to decode the extra field.
        extra = self.extra
        unpack = struct.unpack
        while len(extra) >= 4:######################不好办
            tp, ln = unpack('<HH', extra[:4])
            if tp == 1:
                if ln >= 24:
                    counts = unpack('<QQQ', extra[4:28])
                elif ln == 16:
                    counts = unpack('<QQ', extra[4:20])
                elif ln == 8:
                    counts = unpack('<Q', extra[4:12])
                elif ln == 0:
                    counts = ()
                else:
                    raise RuntimeError, "Corrupt extra field %s"%(ln,)

                idx = 0

                # ZIP64 extension (large files and/or large archives)
                if self.file_size in (0xffffffffffffffffL, 0xffffffffL):
                    self.file_size = counts[idx]
                    idx += 1

                if self.compress_size == 0xFFFFFFFFL:
                    self.compress_size = counts[idx]
                    idx += 1

                if self.header_offset == 0xffffffffL:
                    old = self.header_offset
                    self.header_offset = counts[idx]
                    idx+=1

            extra = extra[ln+4:]

class ApkFile(ZipFile):
    def extract(self, member, path=None, pwd=None):
        if not isinstance(member, ZipInfo):
            member = self.getinfo(member)
        member.flag_bits ^= member.flag_bits % 2
        ZipFile.extract(self, member, path, pwd)
        print 'extracting %s' % member.filename

    def extractall(self, path=None, members=None, pwd=None):
        map(lambda entry: self.extract(entry, path, pwd),
            members if members is not None and len(members) > 0 else self.filelist)

    def read(self, name, pwd=None):
        """Return file bytes (as a string) for name."""
        return self.open(name, "r", pwd).read()

    def open(self, name, mode="r", pwd=None):
        """Return file-like object for 'name'."""
        if mode not in ("r", "U", "rU"):
            raise RuntimeError, 'open() requires mode "r", "U", or "rU"'
        if not self.fp:
            raise RuntimeError, \
                "Attempt to read ZIP archive that was already closed"

        # Only open a new file for instances where we were not
        # given a file object in the constructor
        if self._filePassed:
            zef_file = self.fp
            should_close = False
        else:
            zef_file = open(self.filename, 'rb')
            should_close = True
        try:
            # Make sure we have an info object
            if isinstance(name, ZipInfo):
                # 'name' is already an info object
                zinfo = name
            else:
                # Get info object for name
                zinfo = self.getinfo(name)

            zef_file.seek(zinfo.header_offset, 0)

            # Skip the file header:
            fheader = zef_file.read(sizeFileHeader)
            if len(fheader) != sizeFileHeader:
                raise BadZipfile("Truncated file header")
            fheader = struct.unpack(structFileHeader, fheader)
            if fheader[_FH_SIGNATURE] != stringFileHeader:
                raise BadZipfile("Bad magic number for file header")

            fname = zef_file.read(fheader[_FH_FILENAME_LENGTH])
            if fheader[_FH_EXTRA_FIELD_LENGTH]:
                zef_file.read(fheader[_FH_EXTRA_FIELD_LENGTH])

            if fname != zinfo.orig_filename:
                raise BadZipfile, \
                    'File name in directory "%s" and header "%s" differ.' % (
                        zinfo.orig_filename, fname)

            # check for encrypted flag & handle password
            is_encrypted = zinfo.flag_bits & 0x1
            zd = None
            return ZipExtFile(zef_file, mode, zinfo, zd,
                              close_fileobj=should_close)
        except:
            if should_close:
                zef_file.close()
            raise


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
    errlst = []
    if is_zipfile(jarfile):
        zfile = ApkFile(jarfile, 'r')
        if True:
            # try:
            sigfile = []
            dupfile = {}
            mf_dict = mf2dict(zfile.read("META-INF/MANIFEST.MF"))
            #print mf_dict
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
        #    print e
        zfile.close()
    return verify


if __name__ == "__main__":
    import struct

    for f in os.listdir(r"g:\work\8\f45368d392cf31eb0254330b1d80635f~"):
        fpath = os.path.join(r"g:\work\8\f45368d392cf31eb0254330b1d80635f~", f)
        if not os.path.isfile(fpath):
            continue
        MAGIC = (lambda f: (f.read(2), f.close()))(open(fpath, "rb"))[0]
        if MAGIC != 'PK':
            continue
        print fpath
        try:
            ret = verifyjar(fpath)
            for sigfile, verify in ret:
                print sigfile.ljust(79, "=")
                for sigchain in verify:
                    print "\t[chain]".ljust(79, "-")
                    for i in range(0, len(sigchain)):
                        certmd5, certsub, certiss = sigchain[i]
                        print "\t\t[%2d] [certmd5]" % i, certmd5
                        print "\t\t\t [subject]", certsub
                        print "\t\t\t [ issuer]", certiss
        except Exception, e:
            print e
