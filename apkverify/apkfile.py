#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function, unicode_literals

"""
Read APK files.
"""

import os
import sys
import struct
import binascii
from io import BufferedIOBase
import re

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

# not ready for python 3
try:
    import zlib  # We may need its compression method
    crc32 = zlib.crc32
except ImportError:
    zlib = None
    crc32 = binascii.crc32

__all__ = ['BadZipfile', 'error', 'ZIP_STORED', 'ZIP_DEFLATED', 'is_zipfile',
           'ZipInfo', 'ApkFile', 'LargeZipFile']

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


class BadZipfile(Exception):
    pass


class LargeZipFile(Exception):
    """
    Raised when writing a zipfile, the zipfile requires ZIP64 extensions
    and those extensions are disabled.
    """


error = BadZipfile  # The exception raised by this module

ZIP64_LIMIT = (1 << 31) - 1
ZIP_FILECOUNT_LIMIT = (1 << 16) - 1
ZIP_MAX_COMMENT = (1 << 16) - 1

# constants for Zip file compression methods
ZIP_STORED = 0
ZIP_DEFLATED = 8
# Other ZIP compression methods not supported

# Below are some formats and associated data for reading/writing headers using
# the struct module.  The names and structures of headers/records are those used
# in the PKWARE description of the ZIP file format:
#     http://www.pkware.com/documents/casestudies/APPNOTE.TXT
# (URL valid as of January 2008)

# The 'end of central directory' structure, magic number, size, and indices
# (section V.I in the format document)
structEndArchive = '<4s4H2LH'
stringEndArchive = 'PK\005\006'
sizeEndCentDir = struct.calcsize(structEndArchive)

_ECD_SIGNATURE = 0
_ECD_DISK_NUMBER = 1
_ECD_DISK_START = 2
_ECD_ENTRIES_THIS_DISK = 3
_ECD_ENTRIES_TOTAL = 4
_ECD_SIZE = 5
_ECD_OFFSET = 6
_ECD_COMMENT_SIZE = 7
# These last two indices are not part of the structure as defined in the
# spec, but they are used internally by this module as a convenience
_ECD_COMMENT = 8
_ECD_LOCATION = 9

# The 'central directory' structure, magic number, size, and indices
# of entries in the structure (section V.F in the format document)
structCentralDir = '<4s4B4HL2L5H2L'
stringCentralDir = 'PK\001\002'
sizeCentralDir = struct.calcsize(structCentralDir)

# indexes of entries in the central directory structure
_CD_SIGNATURE = 0
_CD_CREATE_VERSION = 1
_CD_CREATE_SYSTEM = 2
_CD_EXTRACT_VERSION = 3
_CD_EXTRACT_SYSTEM = 4
_CD_FLAG_BITS = 5
_CD_COMPRESS_TYPE = 6
_CD_TIME = 7
_CD_DATE = 8
_CD_CRC = 9
_CD_COMPRESSED_SIZE = 10
_CD_UNCOMPRESSED_SIZE = 11
_CD_FILENAME_LENGTH = 12
_CD_EXTRA_FIELD_LENGTH = 13
_CD_COMMENT_LENGTH = 14
_CD_DISK_NUMBER_START = 15
_CD_INTERNAL_FILE_ATTRIBUTES = 16
_CD_EXTERNAL_FILE_ATTRIBUTES = 17
_CD_LOCAL_HEADER_OFFSET = 18

# The 'local file header' structure, magic number, size, and indices
# (section V.A in the format document)
structFileHeader = '<4s2B4HL2L2H'
stringFileHeader = 'PK\003\004'
sizeFileHeader = struct.calcsize(structFileHeader)

_FH_SIGNATURE = 0
_FH_EXTRACT_VERSION = 1
_FH_EXTRACT_SYSTEM = 2
_FH_GENERAL_PURPOSE_FLAG_BITS = 3
_FH_COMPRESSION_METHOD = 4
_FH_LAST_MOD_TIME = 5
_FH_LAST_MOD_DATE = 6
_FH_CRC = 7
_FH_COMPRESSED_SIZE = 8
_FH_UNCOMPRESSED_SIZE = 9
_FH_FILENAME_LENGTH = 10
_FH_EXTRA_FIELD_LENGTH = 11

# The 'Zip64 end of central directory locator' structure, magic number, and size
structEndArchive64Locator = b'<4sLQL'
stringEndArchive64Locator = b'PK\x06\x07'
sizeEndCentDir64Locator = struct.calcsize(structEndArchive64Locator)

# The 'Zip64 end of central directory' record, magic number, size, and indices
# (section V.G in the format document)
structEndArchive64 = b'<4sQ2H2L4Q'
stringEndArchive64 = b'PK\x06\x06'
sizeEndCentDir64 = struct.calcsize(structEndArchive64)

_CD64_SIGNATURE = 0
_CD64_DIRECTORY_RECSIZE = 1
_CD64_CREATE_VERSION = 2
_CD64_EXTRACT_VERSION = 3
_CD64_DISK_NUMBER = 4
_CD64_DISK_NUMBER_START = 5
_CD64_NUMBER_ENTRIES_THIS_DISK = 6
_CD64_NUMBER_ENTRIES_TOTAL = 7
_CD64_DIRECTORY_SIZE = 8
_CD64_OFFSET_START_CENTDIR = 9


def _check_zipfile(fp):
    try:
        if _EndRecData(fp):
            return True  # file has correct magic number
    except IOError:
        pass
    return False


def is_zipfile(filename):
    """Quickly see if a file is a ZIP file by checking the magic number.

    The filename argument may be a file or file-like object too.
    """
    result = False
    try:
        if hasattr(filename, 'read'):
            result = _check_zipfile(fp=filename)
        else:
            with open(filename, 'rb') as fp:
                result = _check_zipfile(fp)
    except IOError:
        pass
    return result


def _EndRecData64(fpin, offset, endrec):
    """
    Read the ZIP64 end-of-archive records and use that to update endrec
    """
    try:
        fpin.seek(offset - sizeEndCentDir64Locator, 2)
    except IOError:
        # If the seek fails, the file is not large enough to contain a ZIP64
        # end-of-archive record, so just return the end record we were given.
        return endrec

    data = fpin.read(sizeEndCentDir64Locator)
    if len(data) != sizeEndCentDir64Locator:
        return endrec
    sig, diskno, reloff, disks = struct.unpack(structEndArchive64Locator, data)
    if sig != stringEndArchive64Locator:
        return endrec

    if diskno != 0 or disks != 1:
        raise BadZipfile('zipfiles that span multiple disks are not supported')

    # Assume no 'zip64 extensible data'
    fpin.seek(offset - sizeEndCentDir64Locator - sizeEndCentDir64, 2)
    data = fpin.read(sizeEndCentDir64)
    if len(data) != sizeEndCentDir64:
        return endrec
    (sig, sz, create_version, read_version, disk_num, disk_dir,
     dir_count, dir_count_2, dir_size, dir_offset) = \
        struct.unpack(structEndArchive64, data)
    if sig != stringEndArchive64:
        return endrec

    # Update the original endrec using data from the ZIP64 record
    endrec[_ECD_SIGNATURE] = sig
    endrec[_ECD_DISK_NUMBER] = disk_num
    endrec[_ECD_DISK_START] = disk_dir
    endrec[_ECD_ENTRIES_THIS_DISK] = dir_count
    endrec[_ECD_ENTRIES_TOTAL] = dir_count_2
    endrec[_ECD_SIZE] = dir_size
    endrec[_ECD_OFFSET] = dir_offset
    return endrec


def _EndRecData(fpin):
    """Return data from the 'End of Central Directory' record, or None.

    The data is a list of the nine items in the ZIP 'End of central dir'
    record followed by a tenth item, the file seek offset of this record."""

    # Determine file size
    fpin.seek(0, 2)
    filesize = fpin.tell()

    # Check to see if this is ZIP file with no archive comment (the
    # 'end of central directory' structure should be the last item in the
    # file if this is the case).
    try:
        fpin.seek(-sizeEndCentDir, 2)
    except IOError:
        return None
    data = fpin.read()
    if (len(data) == sizeEndCentDir and
            data[0:4] == stringEndArchive and
            data[-2:] == b'\000\000'):
        # the signature is correct and there's no comment, unpack structure
        end_record = struct.unpack(structEndArchive, data)
        end_record = list(end_record)

        # Append a blank comment and record start offset
        end_record.append('')
        end_record.append(filesize - sizeEndCentDir)

        # Try to read the 'Zip64 end of central directory' structure
        return _EndRecData64(fpin, -sizeEndCentDir, end_record)

    # Either this is not a ZIP file, or it is a ZIP file with an archive
    # comment.  Search the end of the file for the 'end of central directory'
    # record signature. The comment is the last item in the ZIP file and may be
    # up to 64K long.  It is assumed that the 'end of central directory' magic
    # number does not appear in the comment.
    max_comment_start = max(filesize - (1 << 16) - sizeEndCentDir, 0)
    fpin.seek(max_comment_start, 0)
    data = fpin.read()
    start = data.rfind(stringEndArchive)
    if start >= 0:
        # found the magic number; attempt to unpack and interpret
        record_data = data[start:start + sizeEndCentDir]
        if len(record_data) != sizeEndCentDir:
            # Zip file is corrupted.
            return None
        end_record = list(struct.unpack(structEndArchive, record_data))
        comment_size = end_record[_ECD_COMMENT_SIZE]  # as claimed by the zip file
        comment = data[start + sizeEndCentDir:start + sizeEndCentDir + comment_size]
        end_record.append(comment)
        end_record.append(max_comment_start + start)

        # Try to read the 'Zip64 end of central directory' structure
        return _EndRecData64(fpin, max_comment_start + start - filesize, end_record)

    # Unable to find a valid end of central directory structure
    return None


class ZipInfo(object):
    """Class with attributes describing each file in the ZIP archive."""

    __slots__ = (
        'orig_filename',
        'filename',
        'date_time',
        'compress_type',
        'comment',
        'extra',
        'create_system',
        'create_version',
        'extract_version',
        'reserved',
        'flag_bits',
        'volume',
        'internal_attr',
        'external_attr',
        'header_offset',
        'header_offset_shuxin',
        'CRC',
        'compress_size',
        'file_size',
        '_raw_time',
    )

    def __init__(self, filename='NoName', date_time=(1980, 1, 1, 0, 0, 0)):
        self.orig_filename = filename  # Original file name in archive

        # Terminate the file name at the first null byte.  Null bytes in file
        # names are used as tricks by viruses in archives.
        null_byte = filename.find(chr(0))
        if null_byte >= 0:
            filename = filename[0:null_byte]
        # This is used to ensure paths in generated ZIP files always use
        # forward slashes as the directory separator, as required by the
        # ZIP format specification.
        if os.sep != '/' and os.sep in filename:
            filename = filename.replace(os.sep, '/')

        self.filename = filename  # Normalized file name
        self.date_time = date_time  # year, month, day, hour, min, sec

        if date_time[0] < 1980:
            raise ValueError('ZIP does not support timestamps before 1980')

        # Standard values:
        self.compress_type = ZIP_STORED  # Type of compression for the file
        self.comment = ''  # Comment for each file
        self.extra = b''  # ZIP extra data
        if sys.platform == 'win32':
            self.create_system = 0  # System which created ZIP archive
        else:
            # Assume everything else is unix-y
            self.create_system = 3  # System which created ZIP archive
        self.create_version = 20  # Version which created ZIP archive
        self.extract_version = 20  # Version needed to extract archive
        self.reserved = 0  # Must be zero
        self.flag_bits = 0  # ZIP flag bits
        self.volume = 0  # Volume number of file header
        self.internal_attr = 0  # Internal attributes
        self.external_attr = 0  # External file attributes
        # Other attributes are set by class ZipFile:
        # header_offset         Byte offset to the file header
        # CRC                   CRC-32 of the uncompressed file
        # compress_size         Size of the compressed file
        # file_size             Size of the uncompressed file

    def FileHeader(self, zip64=None):
        """Return the per-file header as a string."""
        dt = self.date_time
        dos_date = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
        dos_time = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)
        if self.flag_bits & 0x08:
            # Set these to zero because we write them after the file data
            crc_file = compress_size = file_size = 0
        else:
            crc_file = self.CRC
            compress_size = self.compress_size
            file_size = self.file_size

        extra = self.extra

        if zip64 is None:
            zip64 = file_size > ZIP64_LIMIT or compress_size > ZIP64_LIMIT
        if zip64:
            fmt = b'<HHQQ'
            extra += struct.pack(fmt, 1, struct.calcsize(fmt) - 4, file_size, compress_size)
        if file_size > ZIP64_LIMIT or compress_size > ZIP64_LIMIT:
            if not zip64:
                raise LargeZipFile('Filesize would require ZIP64 extensions')
            # File is larger than what fits into a 4 byte integer,
            # fall back to the ZIP64 extension
            file_size = 0xffffffff
            compress_size = 0xffffffff
            self.extract_version = max(45, self.extract_version)
            self.create_version = max(45, self.extract_version)

        filename, flag_bits = self._encodeFilenameFlags()
        header = struct.pack(structFileHeader, stringFileHeader,
                             self.extract_version, self.reserved, flag_bits,
                             self.compress_type, dos_time, dos_date, crc_file,
                             compress_size, file_size,
                             len(filename), len(extra))
        return header + filename + extra

    def _encodeFilenameFlags(self):
        if isinstance(self.filename, unicode_cls):
            try:
                return self.filename.encode('ascii'), self.flag_bits
            except UnicodeEncodeError:
                return self.filename.encode('utf-8'), self.flag_bits | 0x800
        else:
            return self.filename, self.flag_bits

    def _decodeFilename(self):
        if self.flag_bits & 0x800:
            try:
                return self.filename.decode('utf-8')
            except UnicodeDecodeError:
                raise BadZipfile('\'utf8\' codec can\'t decode filename in zip')
        else:
            return self.filename

    def _decodeExtra(self):
        # Try to decode the extra field.
        extra = self.extra
        while len(extra) >= 4:
            tp, ln = struct.unpack('<HH', extra[:4])
            if tp == 1:
                if ln >= 24:
                    counts = struct.unpack('<QQQ', extra[4:28])
                elif ln == 16:
                    counts = struct.unpack('<QQ', extra[4:20])
                elif ln == 8:
                    counts = struct.unpack('<Q', extra[4:12])
                elif ln == 0:
                    counts = ()
                else:
                    raise RuntimeError('Corrupt extra field %s' % (ln,))

                idx = 0

                # ZIP64 extension (large files and/or large archives)
                if self.file_size in (0xffffffffffffffff, 0xffffffff):
                    self.file_size = counts[idx]
                    idx += 1

                if self.compress_size == 0xFFFFFFFF:
                    self.compress_size = counts[idx]
                    idx += 1

                if self.header_offset == 0xffffffff:
                    old = self.header_offset
                    self.header_offset = counts[idx]
                    idx += 1

            extra = extra[ln + 4:]


compressor_names = {
    0: 'store',
    1: 'shrink',
    2: 'reduce',
    3: 'reduce',
    4: 'reduce',
    5: 'reduce',
    6: 'implode',
    7: 'tokenize',
    8: 'deflate',
    9: 'deflate64',
    10: 'implode',
    12: 'bzip2',
    14: 'lzma',
    18: 'terse',
    19: 'lz77',
    97: 'wavpack',
    98: 'ppmd',
}


class ZipExtFile(BufferedIOBase):
    """File-like object for reading an archive member.
       Is returned by ZipFile.open().
    """

    # Max size supported by decompressor.
    MAX_N = 1 << 31 - 1

    # Read from compressed files in 4k blocks.
    MIN_READ_SIZE = 4096

    # Search for universal newlines or line chunks.
    PATTERN = re.compile(r'^(?P<chunk>[^\r\n]+)|(?P<newline>\n|\r\n?)')

    def __init__(self, fileobj, mode, zipinfo, decrypter=None,
                 close_fileobj=False):
        self._fileobj = fileobj
        self._decrypter = decrypter
        self._close_fileobj = close_fileobj

        self._compress_type = zipinfo.compress_type
        self._compress_size = zipinfo.compress_size
        self._compress_left = zipinfo.compress_size

        if self._compress_type == ZIP_DEFLATED:
            self._decompressor = zlib.decompressobj(-15)
        elif self._compress_type != ZIP_STORED:
            descr = compressor_names.get(self._compress_type)
            if descr:
                raise NotImplementedError('compression type %d (%s)' % (self._compress_type, descr))
            else:
                raise NotImplementedError('compression type %d' % (self._compress_type,))
        self._unconsumed = b''

        self._readbuffer = b''
        self._offset = 0

        self._universal = b'U' in mode
        self.newlines = None

        # Adjust read size for encrypted files since the first 12 bytes
        # are for the encryption/password information.
        if self._decrypter is not None:
            self._compress_left -= 12

        self.mode = mode
        self.name = zipinfo.filename

        if hasattr(zipinfo, 'CRC'):
            self._expected_crc = zipinfo.CRC
            self._running_crc = crc32(b'') & 0xffffffff
        else:
            self._expected_crc = None

    def readable(self):
        return True

    def read(self, n=-1):
        """Read and return up to n bytes.
        If the argument is omitted, None, or negative, data is read and returned until EOF is reached..
        """
        buf = b''
        if n is None:
            n = -1
        while True:
            if n < 0:
                data = self.read1(n)
            elif n > len(buf):
                data = self.read1(n - len(buf))
            else:
                return buf
            if len(data) == 0:
                return buf
            buf += data

    def _update_crc(self, newdata, eof):
        # Update the CRC using the given data.
        if self._expected_crc is None:
            # No need to compute the CRC if we don't have a reference value
            return
        self._running_crc = crc32(newdata, self._running_crc) & 0xffffffff
        # Check the CRC if we're at the end of the file
        if eof and self._running_crc != self._expected_crc:
            raise BadZipfile('Bad CRC-32 for file %r' % self.name)

    def read1(self, n):
        """Read up to n bytes with at most one read() system call."""

        # Simplify algorithm (branching) by transforming negative n to large n.
        if n < 0 or n is None:
            n = self.MAX_N

        # Bytes available in read buffer.
        len_readbuffer = len(self._readbuffer) - self._offset

        # Read from file.
        if self._compress_left > 0 and n > len_readbuffer + len(self._unconsumed):
            nbytes = n - len_readbuffer - len(self._unconsumed)
            nbytes = max(nbytes, self.MIN_READ_SIZE)
            nbytes = min(nbytes, self._compress_left)

            data = self._fileobj.read(nbytes)
            self._compress_left -= len(data)

            if data and self._decrypter is not None:
                data = b''.join(map(self._decrypter, data))

            if self._compress_type == ZIP_STORED:
                self._update_crc(data, eof=(self._compress_left == 0))
                self._readbuffer = self._readbuffer[self._offset:] + data
                self._offset = 0
            else:
                # Prepare deflated bytes for decompression.
                self._unconsumed += data

        # Handle unconsumed data.
        if (len(self._unconsumed) > 0 and n > len_readbuffer and
                self._compress_type == ZIP_DEFLATED):
            data = self._decompressor.decompress(
                self._unconsumed,
                max(n - len_readbuffer, self.MIN_READ_SIZE)
            )

            self._unconsumed = self._decompressor.unconsumed_tail
            eof = len(self._unconsumed) == 0 and self._compress_left == 0
            if eof:
                data += self._decompressor.flush()

            self._update_crc(data, eof=eof)
            self._readbuffer = self._readbuffer[self._offset:] + data
            self._offset = 0

        # Read from buffer.
        data = self._readbuffer[self._offset: self._offset + n]
        self._offset += len(data)
        return data

    def close(self):
        try:
            if self._close_fileobj:
                self._fileobj.close()
        finally:
            super(ZipExtFile, self).close()


class ApkFile(object):
    """ Class with methods to open, read, write, close, list zip files.

    z = ZipFile(file, mode='r', compression=ZIP_STORED, allowZip64=False)

    file: Either the path to the file, or a file-like object.
          If it is a path, the file will be opened and closed by ZipFile.
    mode: The mode can be either read 'r', write 'w' or append 'a'.
    compression: ZIP_STORED (no compression) or ZIP_DEFLATED (requires zlib).
    allowZip64: if True ZipFile will create files with ZIP64 extensions when
                needed, otherwise it will raise an exception when this would
                be necessary.

    """

    fp = None  # Set here since __del__ checks it

    def __init__(self, file, mode='r', compression=ZIP_STORED, allowZip64=False):
        self.debug = 0  # Level of printing: 0 through 3
        self.NameToInfo = {}  # Find file info given name
        self.filelist = []  # List of ZipInfo instances for archive
        if isinstance(file, basestring_cls):
            self._filePassed = 0
            self.filename = file
            self.fp = open(file, 'rb')
        else:
            self._filePassed = 1
            self.fp = file
            self.filename = getattr(file, 'name', None)

        try:
            self._RealGetContents()
        except:
            fp = self.fp
            self.fp = None
            if not self._filePassed:
                fp.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def _RealGetContents(self):
        """Read in the table of contents for the ZIP file."""
        fp = self.fp
        try:
            endrec = _EndRecData(fp)
        except IOError:
            raise BadZipfile('File is not a zip file')
        if not endrec:
            raise BadZipfile('File is not a zip file')
        if self.debug > 1:
            print(endrec)
        size_cd = endrec[_ECD_SIZE]  # bytes in central directory
        offset_cd = endrec[_ECD_OFFSET]  # offset of central directory
        self.size_cd = size_cd
        self.offset_cd = offset_cd
        self._comment = endrec[_ECD_COMMENT]  # archive comment

        # 'concat' is zero, unless zip was concatenated to another file
        concat = endrec[_ECD_LOCATION] - size_cd - offset_cd
        if endrec[_ECD_SIGNATURE] == stringEndArchive64:
            # If Zip64 extension structures are present, account for them
            concat -= (sizeEndCentDir64 + sizeEndCentDir64Locator)

        if self.debug > 2:
            inferred = concat + offset_cd
            print('given, inferred, offset', offset_cd, inferred, concat)
        # self.start_dir:  Position of start of central directory
        self.start_dir = offset_cd + concat
        fp.seek(self.start_dir, 0)
        data = fp.read(size_cd)
        fp = StringIO(data)
        total = 0
        while total < size_cd:
            centdir = fp.read(sizeCentralDir)
            if len(centdir) != sizeCentralDir:
                raise BadZipfile('Truncated central directory')
            centdir = struct.unpack(structCentralDir, centdir)
            if centdir[_CD_SIGNATURE] != stringCentralDir:
                raise BadZipfile('Bad magic number for central directory')
            if self.debug > 2:
                print(centdir)
            filename = fp.read(centdir[_CD_FILENAME_LENGTH])
            # Create ZipInfo instance to store file information
            x = ZipInfo(filename)
            x.extra = fp.read(centdir[_CD_EXTRA_FIELD_LENGTH])
            x.comment = fp.read(centdir[_CD_COMMENT_LENGTH])
            x.header_offset = centdir[_CD_LOCAL_HEADER_OFFSET]
            (x.create_version, x.create_system, x.extract_version, x.reserved,
             x.flag_bits, x.compress_type, t, d,
             x.CRC, x.compress_size, x.file_size) = centdir[1:12]
            x.volume, x.internal_attr, x.external_attr = centdir[15:18]
            # Convert date/time code to (year, month, day, hour, min, sec)
            x._raw_time = t
            x.date_time = ((d >> 9) + 1980, (d >> 5) & 0xF, d & 0x1F,
                           t >> 11, (t >> 5) & 0x3F, (t & 0x1F) * 2)

            x._decodeExtra()
            x.header_offset_shuxin = x.header_offset
            x.header_offset = x.header_offset + concat
            x.filename = x._decodeFilename()
            self.filelist.append(x)
            self.NameToInfo[x.filename] = x

            # update total bytes read from central directory
            total = (total + sizeCentralDir + centdir[_CD_FILENAME_LENGTH]
                     + centdir[_CD_EXTRA_FIELD_LENGTH]
                     + centdir[_CD_COMMENT_LENGTH])

            if self.debug > 2:
                print('total', total)

    def namelist(self):
        """Return a list of file names in the archive."""
        file_names = []
        for data in self.filelist:
            file_names.append(data.filename)
        return file_names

    def infolist(self):
        """Return a list of class ZipInfo instances for files in the
        archive."""
        return self.filelist

    def printdir(self):
        """Print a table of contents for the zip file."""
        print('%-46s %19s %12s' % ('File Name', 'Modified    ', 'Size'))
        for zip_nfo in self.filelist:
            date = '%d-%02d-%02d %02d:%02d:%02d' % zip_nfo.date_time[:6]
            print('%-46s %s %12d' % (zip_nfo.filename, date, zip_nfo.file_size))

    def testzip(self):
        """Read all the files and check the CRC."""
        chunk_size = 2 ** 20
        for zip_nfo in self.filelist:
            try:
                # Read by chunks, to avoid an OverflowError or a
                # MemoryError with very large embedded files.
                with self.open(zip_nfo.filename, 'r') as f:
                    while f.read(chunk_size):  # Check CRC-32
                        pass
            except BadZipfile:
                return zip_nfo.filename

    def getinfo(self, name):
        """Return the instance of ZipInfo given 'name'."""
        info = self.NameToInfo.get(name)
        if info is None:
            raise KeyError(
                'There is no item named %r in the archive' % name)

        return info

    def read(self, name, pwd=None):
        """Return file bytes (as a string) for name."""
        try:
            return self.open(name, 'r', pwd).read()
        except Exception as e_primary:
            try:
                return self.open_robust(name, 'r', pwd).read()
            except Exception as e:
                pass
            raise e_primary

    def open(self, name, mode='r', pwd=None):
        """Return file-like object for 'name'."""
        if mode not in ('r', 'U', 'rU'):
            raise RuntimeError('open() requires mode \'r\', \'U\', or \'rU\'')
        if not self.fp:
            raise RuntimeError('Attempt to read ZIP archive that was already closed')

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
                zip_nfo = name
            else:
                # Get info object for name
                zip_nfo = self.getinfo(name)

            zef_file.seek(zip_nfo.header_offset, 0)

            # Skip the file header:
            file_header = zef_file.read(sizeFileHeader)
            if len(file_header) != sizeFileHeader:
                raise BadZipfile('Truncated file header')
            file_header = struct.unpack(structFileHeader, file_header)
            if file_header[_FH_SIGNATURE] != stringFileHeader:
                raise BadZipfile('Bad magic number for file header')

            file_name = zef_file.read(file_header[_FH_FILENAME_LENGTH])
            if file_header[_FH_EXTRA_FIELD_LENGTH]:
                zef_file.read(file_header[_FH_EXTRA_FIELD_LENGTH])

            if file_name != zip_nfo.orig_filename:
                raise BadZipfile('File name in directory \'%s\' and header \'%s\' differ.' % (
                    zip_nfo.orig_filename, file_name))

            # check for encrypted flag & handle password

            zd = None
            return ZipExtFile(zef_file, mode, zip_nfo, zd,
                              close_fileobj=should_close)
        except:
            if should_close:
                zef_file.close()
            raise

    def open_robust(self, name, mode='r', pwd=None):
        """Return file-like object for 'name'."""
        if mode not in ('r', 'U', 'rU'):
            raise RuntimeError('open() requires mode \'r\', \'U\', or \'rU\'')
        if not self.fp:
            raise RuntimeError('Attempt to read ZIP archive that was already closed')

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
                zip_nfo = name
            else:
                # Get info object for name
                zip_nfo = self.getinfo(name)

            zef_file.seek(zip_nfo.header_offset_shuxin, 0)

            # Skip the file header:
            file_header = zef_file.read(sizeFileHeader)
            if len(file_header) != sizeFileHeader:
                raise BadZipfile('Truncated file header')
            file_header = struct.unpack(structFileHeader, file_header)
            if file_header[_FH_SIGNATURE] != stringFileHeader:
                raise BadZipfile('Bad magic number for file header')

            file_name = zef_file.read(file_header[_FH_FILENAME_LENGTH])
            if file_header[_FH_EXTRA_FIELD_LENGTH]:
                zef_file.read(file_header[_FH_EXTRA_FIELD_LENGTH])

            if file_name != zip_nfo.orig_filename:
                raise BadZipfile('File name in directory \'%s\' and header \'%s\' differ.' % (
                    zip_nfo.orig_filename, file_name))

            # check for encrypted flag & handle password

            zd = None
            return ZipExtFile(zef_file, mode, zip_nfo, zd,
                              close_fileobj=should_close)
        except:
            if should_close:
                zef_file.close()
            raise

    def __del__(self):
        """Call the 'close()' method in case the user forgot."""
        self.close()

    def close(self):
        """Close the file, and for mode 'w' and 'a' write the ending
        records."""
        if self.fp is None:
            return

        try:
            pass
        finally:
            fp = self.fp
            self.fp = None
            if not self._filePassed:
                fp.close()
