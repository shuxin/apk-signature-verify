#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function, unicode_literals

import binascii
import logging
import hashlib
import struct
import math

from asn1crypto import cms, x509
from asn1crypto import algos, keys
from asn1crypto import pem
from asn1crypto.util import int_to_bytes as long_to_bytes
from asn1crypto.util import int_from_bytes as bytes_to_long
from asn1crypto._types import bytes_to_list as _list
from asn1crypto._types import chr_cls as _chr

DEBUG = False

#######################################################################################################################
# DSA RSA ECDSA ( pure python without openssl )
#######################################################################################################################

secp192k1 = {'p': 2 ** 192 - 2 ** 32 - 2 ** 12 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 3 - 1, 'a': 0, 'b': 3,
             'Gx': 0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D,
             'Gy': 0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D,
             'n': 0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D}
secp192r1 = {'p': 2 ** 192 - 2 ** 64 - 1, 'a': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC,
             'b': 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1,
             'Gx': 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
             'Gy': 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811,
             'n': 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831}
secp224k1 = {'p': 2 ** 224 - 2 ** 32 - 2 ** 12 - 2 ** 11 - 2 ** 9 - 2 ** 7 - 2 ** 4 - 2 - 1, 'a': 0, 'b': 5,
             'Gx': 0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C,
             'Gy': 0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5,
             'n': 0x010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7}
secp224r1 = {'p': 2 ** 224 - 2 ** 96 + 1, 'a': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE,
             'b': 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4,
             'Gx': 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
             'Gy': 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34,
             'n': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D}
secp256k1 = {'p': 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1, 'a': 0, 'b': 7,
             'Gx': 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
             'Gy': 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
             'n': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141}
secp256r1 = {'p': 2 ** 224 * (2 ** 32 - 1) + 2 ** 192 + 2 ** 96 - 1,
             'a': 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
             'b': 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
             'Gx': 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
             'Gy': 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
             'n': 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551}
secp384r1 = {'p': 2 ** 384 - 2 ** 128 - 2 ** 96 + 2 ** 32 - 1,
             'a': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
             'b': 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
             'Gx': 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
             'Gy': 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
             'n': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973}
secp521r1 = {'p': 2 ** 521 - 1,
             'a': 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC,
             'b': 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
             'Gx': 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
             'Gy': 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
             'n': 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409}

EC_CURVE = {
    '1.2.840.10045.3.1.1': secp192r1, '1.3.132.0.33': secp224r1, '1.2.840.10045.3.1.7': secp256r1,
    '1.3.132.0.34': secp384r1, '1.3.132.0.35': secp521r1, 'secp192r1': secp192r1, 'secp224r1': secp224r1,
    'secp256r1': secp256r1, 'secp384r1': secp384r1, 'secp521r1': secp521r1, 'NIST192p': secp192r1,
    'NIST224p': secp224r1, 'NIST256p': secp256r1, 'NIST384p': secp384r1, 'NIST521p': secp521r1,
    '1.3.132.0.10': secp256k1, 'secp256k1': secp256k1}


#######################################################################################################################


def _rsa_decode(a, p, n):
    result = a % n
    remainders = []
    while p != 1:
        remainders.append(p & 1)
        p = p >> 1
    while remainders:
        rem = remainders.pop()
        result = ((a ** rem) * result ** 2) % n
    return result


def _inverse(z, a):
    if 0 < z < a and a > 0:
        j, i = z, a
        y1, y2 = 1, 0
        while j > 0:
            q, j, i = divmod(i, j) + (j,)
            y1, y2 = y2 - y1 * q, y1
        if i == 1:
            return y2 % a
    raise Exception('Inverse Error')


def _dsa_verify(p, q, g, pub, H, r, s):
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    w = _inverse(s, q)
    u1, u2 = (H * w) % q, (r * w) % q
    v1 = pow(g, u1, p)
    v2 = pow(pub, u2, p)
    v = ((v1 * v2) % p) % q
    return v == r


def inverse_mod(a, m):
    """Inverse of a mod m."""
    if a < 0 or m <= a:
        a = a % m
    # From Ferguson and Schneier, roughly:
    c, d = a, m
    uc, vc, ud, vd = 1, 0, 0, 1
    while c != 0:
        q, c, d = divmod(d, c) + (c,)
        uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc
    # At this point, d is the GCD, and ud*a+vd*m = d.
    # If d == 1, this means that ud is a inverse.
    assert d == 1
    if ud > 0:
        return ud
    else:
        return ud + m


class ECPoint(object):
    def __init__(self, p=None, a=None, b=None, x=None, y=None, n=None):
        self.__p = p
        self.__a = a
        self.__b = b
        self.__x = x
        self.__y = y
        self.__n = n

    def __eq__(self, other):
        if self.__a != other.__a:
            return False
        if self.__a != other.__a:
            return False
        if self.__b != other.__b:
            return False
        if self.__x != other.__x:
            return False
        if self.__y != other.__y:
            return False
        if self.__n != other.__n:
            return False
        return True

    def __add__(self, other):
        if other == INFINITY:
            return self
        if self == INFINITY:
            return other
        if self.__x == other.__x:
            if (self.__y + other.__y) % self.__p == 0:
                return INFINITY
            else:
                return self.double()
        l = ((other.__y - self.__y) * inverse_mod(other.__x - self.__x, self.__p)) % self.__p
        x3 = (l * l - self.__x - other.__x) % self.__p
        y3 = (l * (self.__x - x3) - self.__y) % self.__p
        return ECPoint(self.__p, self.__a, self.__b, x3, y3)

    def __mul__(self, other):
        """Multiply a point by an integer."""

        def leftmost_bit(x):
            assert x > 0
            result = 1
            while result <= x:
                result = 2 * result
            return result // 2

        e = other
        if self.__p:
            e = e % self.__p
        if e == 0:
            return INFINITY
        if self == INFINITY:
            return INFINITY
        assert e > 0
        e3 = 3 * e
        negative_self = ECPoint(self.__p, self.__a, self.__b, self.__x, -self.__y, self.__n)
        i = leftmost_bit(e3) // 2
        result = self
        # print('Multiplying %s by %d (e3 = %d):' % (self, other, e3))
        while i > 1:
            result = result.double()
            if (e3 & i) != 0 and (e & i) == 0:
                result = result + self
            if (e3 & i) == 0 and (e & i) != 0:
                result = result + negative_self
            # print('. . . i = %d, result = %s' % ( i, result ))
            i = i // 2
        return result

    def __rmul__(self, other):
        """Multiply a point by an integer."""
        return self * other

    def __str__(self):
        if self == INFINITY:
            return 'infinity'
        return '(%d,%d)' % (self.__x, self.__y)

    def double(self):
        """Return a new point that is twice the old."""
        if self == INFINITY:
            return INFINITY
        # X9.62 B.3:
        l = ((3 * self.__x * self.__x + self.__a) * inverse_mod(2 * self.__y, self.__p)) % self.__p
        x3 = (l * l - 2 * self.__x) % self.__p
        y3 = (l * (self.__x - x3) - self.__y) % self.__p
        return ECPoint(self.__p, self.__a, self.__b, x3, y3)

    def x(self):
        return self.__x

    def y(self):
        return self.__y


INFINITY = ECPoint()


def _ecdsa_verify(ec_curve, ec_key, H, r, s):
    n = ec_curve['n']
    if r < 1 or r > n - 1:
        return False
    if s < 1 or s > n - 1:
        return False
    c = inverse_mod(s, n)
    u1 = (H * c) % n
    u2 = (r * c) % n
    G = ECPoint(
        ec_curve['p'],
        ec_curve['a'],
        ec_curve['b'],
        ec_curve['Gx'],
        ec_curve['Gy'],
        ec_curve['n'])
    point = ECPoint(
        ec_curve['p'],
        ec_curve['a'],
        ec_curve['b'],
        ec_key['x'],
        ec_key['y'])
    xy = G * u1 + point * u2
    v = xy.x() % n
    return v == r


########################################################################################################################


FLAG_NOTHING = 0
FLAG_256_PSS = 1
FLAG_512_PSS = 2


def _pss_mgf1(_dst, _src, hash_flag):
    _h = hashlib.sha256
    if hash_flag == FLAG_256_PSS:
        _h = hashlib.sha256
    if hash_flag == FLAG_512_PSS:
        _h = hashlib.sha512
    dst_len = len(_dst)
    dst_lst = _list(_dst)
    tmp = 0
    while dst_len > 0:
        tmp_lst = _list(_h(_src + struct.pack('>I', tmp)).digest())
        mask_len = min(dst_len, len(_src))
        for i in range(0, mask_len):
            dst_lst[len(_dst) - dst_len + i] ^= tmp_lst[i]
        dst_len -= mask_len
        tmp += 1
    return b''.join([_chr(c) for c in dst_lst])


def _pss_verify(_buf, file_hash, hash_flag):
    _h = hashlib.sha256
    if hash_flag == FLAG_256_PSS:
        _h = hashlib.sha256
    if hash_flag == FLAG_512_PSS:
        _h = hashlib.sha512
    print(len(_buf))
    _xxx = _buf[:-1 - len(file_hash)]
    _yyy = _buf[-1 - len(file_hash):-1]
    ____ = _buf[-1:0]  # b'\xbc'
    _dec = _pss_mgf1(_xxx, _yyy, hash_flag)
    salt = _dec[-len(file_hash):]
    _tmp = b'\0' * 8 + file_hash + salt
    _zzz = _h(_tmp).digest()
    return _yyy == _zzz


'''
                                 +-----------+
                                 |     M     |
                                 +-----------+
                                       |
                                       V
                                     Hash
                                       |
                                       V
                         +--------+----------+----------+
                    M' = |Padding1|  mHash   |   salt   |
                         +--------+----------+----------+
                                        |
              +--------+----------+     V
        DB =  |Padding2|   salt   |   Hash
              +--------+----------+     |
                        |               |
                        V               |
                       xor <--- MGF <---|
                        |               |
                        |               |
                        V               V
              +-------------------+----------+--+
        EM =  |    maskedDB       |     H    |bc|
              +-------------------+----------+--+
'''


def fix_dsa_hash_length(H, q):
    # if the digest length is greater than the size of q use the
    # BN_num_bits(dsa->q) leftmost bits of the digest, see fips 186-3, 4.2
    bytes_high = H
    bytes_h = long_to_bytes(bytes_high)
    bytes_q = long_to_bytes(q)
    if len(bytes_h) > len(bytes_q):
        bytes_high = bytes_to_long(bytes_h[:len(bytes_q)])
    return bytes_high


def sig_verify(signature, public_key_info, file_hash_hex, hash_flag=FLAG_NOTHING):
    try:
        file_hash = binascii.a2b_hex(file_hash_hex)
        algorithm0 = public_key_info['algorithm']['algorithm'].dotted
        parameters = public_key_info['algorithm']['parameters'].native

        if algorithm0 == '1.2.840.113549.1.1.1':
            mod = public_key_info['public_key'].native['modulus']
            exp = public_key_info['public_key'].native['public_exponent']
            enc = bytes_to_long(signature)
            dec = _rsa_decode(enc, exp, mod)
            decoded_sig = long_to_bytes(dec)
            if hash_flag == FLAG_NOTHING:
                idx = 0
                for byte in decoded_sig:
                    if byte in [b for b in b'\x00\x01\xff']:
                        idx += 1
                    if byte in [b for b in b'\x00']:
                        break
                decoded_bytes = decoded_sig[idx:]
                v = algos.DigestInfo.load(decoded_bytes)['digest'].native
                # if DEBUG:print binascii.b2a_hex(file_hash), binascii.b2a_hex(v)
                return file_hash == v
            else:
                return _pss_verify(decoded_sig, file_hash, hash_flag)
        elif algorithm0 == '1.2.840.10040.4.1':
            pub = public_key_info['public_key'].native
            p = parameters['p']
            q = parameters['q']
            g = parameters['g']
            # print(encoded)
            rs = algos.DSASignature.load(signature)
            r = rs['r'].native
            s = rs['s'].native
            bytes_hign = bytes_to_long(file_hash)
            bytes_hign = fix_dsa_hash_length(bytes_hign, q)
            return _dsa_verify(p, q, g, pub, bytes_hign, r, s)
        elif algorithm0 == '1.2.840.10045.2.1':
            # {iso(1) member-body(2) us(840) ansi-x962(10045) keyType(2) ecPublicKey(1)}
            pubkey = public_key_info['public_key'].native
            cert_curve = parameters
            if pubkey[0] != b'\x04'[0]:
                # POINT_NULL         = (0x00,)
                # POINT_COMPRESSED   = (0x02, 0x03)
                # POINT_UNCOMPRESSED = (0x04,)
                return False
            ec_curve = EC_CURVE.get(str(cert_curve))
            # print(ec_curve)
            coord_size_p = int(math.ceil(math.log(ec_curve.get('p'), 2) / 8))
            coord_size_n = int(math.ceil(math.log(ec_curve.get('n'), 2) / 8))
            coord_size = coord_size_p  # p or n ?
            ec_key = {
                'x': bytes_to_long(pubkey[1:coord_size + 1]),
                'y': bytes_to_long(pubkey[coord_size + 1:]),
            }
            rs = algos.DSASignature.load(signature)
            r = rs['r'].native
            s = rs['s'].native
            H = bytes_to_long(file_hash)
            H = fix_dsa_hash_length(H, ec_curve.get('p'))
            return _ecdsa_verify(ec_curve, ec_key, H, r, s)
    except Exception as e:
        logging.exception(e)
    # print('unknown algorithm',algorithm0)
    return None


#######################################################
# 额外处理
#######################################################


class cert():
    def __init__(self, c):
        raw_pem = binascii.b2a_base64(c.dump()).replace(b'\n', b'')
        self.certobj = c
        self.certder = self.certobj.dump()
        self.fgprint = hashlib.sha1(self.certder).hexdigest()
        # self.issuer = self.certobj.issuer.human_friendly
        # self.subject = self.certobj.subject.human_friendly
        # self.certmd5 = hashlib.md5(raw_pem).hexdigest()
        # self.certpem = '-----BEGIN CERTIFICATE-----\r\n%s\r\n-----END CERTIFICATE-----\r\n' % '\r\n'.join(
        # raw_pem[pos:pos+64] for pos in xrange(0, len(raw_pem), 64))
        # f = open('%s.crt' % (self.fgprint,),'wb')
        # f.write(self.certpem)
        # f.close()
        self.authkey = None
        self.subjkey = None
        if self.certobj.authority_key_identifier:
            self.authkey = binascii.b2a_hex(self.certobj.authority_key_identifier)
        if self.certobj.key_identifier:
            self.subjkey = binascii.b2a_hex(self.certobj.key_identifier)
        self.pub_key = self.certobj.public_key

    def dump(self):
        return (
            self.fgprint,
            self.certobj.issuer.human_friendly,
            self.certobj.subject.human_friendly,
            pem.armor('CERTIFICATE', self.certder),
        )


# 验证证书链父子关系(自签根证书，父子均为自身)
def verify_certificate(c, pc):
    # TODO: need a new way
    c_signature_algorithm = c['signature_algorithm']['algorithm'].dotted
    c_tbs_encoded = c['tbs_certificate'].dump()
    if c_signature_algorithm == '1.2.840.113549.1.1.4':  # RSA
        tbs_hash_hex = hashlib.md5(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == '1.2.840.113549.1.1.5':
        tbs_hash_hex = hashlib.sha1(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == '1.2.840.113549.1.1.11':
        tbs_hash_hex = hashlib.sha256(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == '1.2.840.113549.1.1.12':
        tbs_hash_hex = hashlib.sha384(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == '1.2.840.113549.1.1.13':
        tbs_hash_hex = hashlib.sha512(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == '1.2.840.10040.4.3':  # DSA
        tbs_hash_hex = hashlib.sha1(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == '2.16.840.1.101.3.4.3.2':
        tbs_hash_hex = hashlib.sha256(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == '1.2.840.10045.4.1':  # ecdsa
        tbs_hash_hex = hashlib.sha1(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == '1.2.840.10045.4.3.2':
        tbs_hash_hex = hashlib.sha256(c_tbs_encoded).hexdigest()
    else:
        tbs_hash_hex = ''
    pub_key = pc.public_key
    return sig_verify(c.signature, pub_key, tbs_hash_hex)


def verify_chain(verified_certs, relation_cache, cert_cache):
    verified_chains = []  # 完全验证的证书链(二维，没链就仅有自己)
    for chain_head in verified_certs:
        one_verified_chain = [chain_head]
        on_chain = chain_head
        while cert_cache[on_chain].authkey and cert_cache[on_chain].authkey in relation_cache:  # 如果有父证书
            c = on_chain
            pc = relation_cache[cert_cache[on_chain].authkey]
            if c == pc:
                break
            if verify_certificate(cert_cache[c].certobj, cert_cache[pc].certobj):
                one_verified_chain.append(pc)  # 附加到链上
            on_chain = pc  # 继续验证再父一级证书
        if DEBUG:  # 理论上是要验证根证书自签的，Android不需要，Android只是借用证书格式实际上只用公钥部分，ssl必须
            rootca = one_verified_chain[-1]
            self_signed = verify_certificate(cert_cache[rootca].certobj, cert_cache[rootca].certobj)
            if not self_signed:
                continue
        verified_chains.append(one_verified_chain)
    return verified_chains


def check_sig_pkcs7(sigbuf=b'buf of CERT.RSA', sfbuf=b'buf of CERT.SF'):
    cert_cache = {}  # 所有出现的证书
    relation_cache = {}  # 记录签发关系
    verified_certs = []  # 完全验证的证书
    sfhash = {
        '1.2.840.113549.2.5': ('MD5', hashlib.md5(sfbuf).hexdigest()),
        '1.3.14.3.2.26': ('SHA1', hashlib.sha1(sfbuf).hexdigest()),
        '2.16.840.1.101.3.4.2.1': ('SHA256', hashlib.sha256(sfbuf).hexdigest()),
        '2.16.840.1.101.3.4.2.2': ('SHA384', hashlib.sha384(sfbuf).hexdigest()),
        '2.16.840.1.101.3.4.2.3': ('SHA512', hashlib.sha512(sfbuf).hexdigest()),
        '2.16.840.1.101.3.4.2.4': ('SHA244', hashlib.sha224(sfbuf).hexdigest()),
    }
    # '1.2.840.10045.4.3.2':#{iso(1) member-body(2) us(840)
    # ansi-x962(10045) signatures(4) ecdsa-with-SHA2(3) ecdsa-with-SHA256(2)}
    p = cms.ContentInfo.load(sigbuf)
    for c in p[u'content'][u'certificates']:
        # print c.raw_der_data
        # print c.tbsCertificate
        # print c.tbsCertificate.pub_key_info.algType
        # print c.tbsCertificate.pub_key_info.key
        mycert = cert(c.chosen)
        cert_cache[mycert.fgprint] = mycert
        if mycert.subjkey:
            relation_cache[mycert.subjkey] = mycert.fgprint
        for r in p['content']['signer_infos']:
            # print r.signature
            # print r.digest_algorithm
            # print Hash_Algorithm_OID.get(r.digest_algorithm)
            file_digest_oid = r['digest_algorithm']['algorithm'].dotted
            file_digest, file_hash = sfhash.get(file_digest_oid, ['UNKNOWN', ''])
            v = sig_verify(r['signature'].native, mycert.pub_key, file_hash)
            if v:
                verified_certs.append(mycert.fgprint)
    verified_chains = verify_chain(verified_certs, relation_cache, cert_cache)
    all_certs_with_out_object = {}
    for fgprint, mycert in cert_cache.items():
        all_certs_with_out_object[mycert.fgprint] = mycert.dump()
    return verified_chains, all_certs_with_out_object


def extract_list_by_int_prefix(data):
    datas = []
    idx = 0
    while idx + 4 <= len(data):
        i = struct.unpack('<L', data[idx:idx + 4])[0]
        s = data[idx + 4:idx + 4 + i]
        idx += 4 + i
        datas.append(s)
        # print 'debug',idx,len(data)
        # buff2 = sig[idx:]
        # print repr(buff2)
    if idx != len(data):
        pass  # print('warn',idx,len(data))
    return datas


def check_sig_v2(signedData, signatures, publicKeyBytes):
    cert_cache = {}  # 所有出现的证书
    relation_cache = {}  # 记录签发关系
    verified_certs = []  # 完全验证的证书
    hashDigestType = {
        0x0101: ('SHA256', FLAG_256_PSS),  # 'SHA256withRSA/PSS', 'SIGNATURE_RSA_PSS_WITH_SHA256',),
        0x0102: ('SHA512', FLAG_512_PSS),  # 'SHA512withRSA/PSS', 'SIGNATURE_RSA_PSS_WITH_SHA512',),
        0x0103: ('SHA256', FLAG_NOTHING),  # 'SHA256withRSA',      'SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256',),
        0x0104: ('SHA512', FLAG_NOTHING),  # 'SHA512withRSA',      'SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512',),
        0x0201: ('SHA256', FLAG_NOTHING),  # 'SHA256withECDSA',    'SIGNATURE_ECDSA_WITH_SHA256',),
        0x0202: ('SHA512', FLAG_NOTHING),  # 'SHA512withECDSA',    'SIGNATURE_ECDSA_WITH_SHA512',),
        0x0301: ('SHA256', FLAG_NOTHING),  # 'SHA256withDSA',      'SIGNATURE_DSA_WITH_SHA256',),
    }
    '''
RSA：1024、2048、4096、8192、16384
EC：NIST P-256、P-384、P-521
DSA：1024、2048、3072
    '''
    algs_for_zip = []
    algs_for_sig = []
    alg_sig_best = None
    # alg_zip_best = None
    ret = 'v2BadCertSig'
    idx = 0
    for signature in extract_list_by_int_prefix(signatures):
        while idx + 8 <= len(signature):
            alg = struct.unpack('<L', signature[idx:idx + 4])[0]
            i = struct.unpack('<L', signature[idx + 4:idx + 8])[0]
            s = signature[idx + 8:idx + 8 + i]
            idx += 8 + i
            hash_type, hash_flag = hashDigestType.get(alg, ('UNKNOWN', 0))
            algs_for_sig.append((hash_type, s))
            if alg_sig_best is None:
                if hash_type:
                    alg_sig_best = (hash_type, hash_flag, s)
                else:
                    pass  # print('unsupport alg',alg)
            elif alg_sig_best[0] == 'SHA256' and hash_type == 'SHA512':
                alg_sig_best = (hash_type, hash_flag, s)
            else:
                pass
    if alg_sig_best:
        file_digest, hash_flag, siginfo = alg_sig_best
        public_key_info = keys.PublicKeyInfo.load(publicKeyBytes)
        sf_hash = {
            # 'MD5': hashlib.md5(hashs).hexdigest(),
            # 'SHA1': hashlib.sha1(hashs).hexdigest(),
            'SHA256': hashlib.sha256(signedData).hexdigest(),
            # 'SHA384': hashlib.sha384(signedData).hexdigest(),
            'SHA512': hashlib.sha512(signedData).hexdigest(),
        }
        file_hash = sf_hash.get(file_digest, '')
        v = sig_verify(siginfo, public_key_info, file_hash, hash_flag)
        if not v:
            ret = 'v2PubkeySigError'
        else:
            data2 = extract_list_by_int_prefix(signedData)
            if len(data2) >= 2:  # ignore additional attributes
                digests, certificates = data2[:2]
                for digest in extract_list_by_int_prefix(digests):
                    idx = 0
                    while idx + 8 <= len(digest):
                        alg2 = struct.unpack('<L', digest[idx:idx + 4])[0]
                        i2 = struct.unpack('<L', digest[idx + 4:idx + 8])[0]
                        s2 = digest[idx + 8:idx + 8 + i2]
                        idx += 8 + i2
                        hash_type = hashDigestType.get(alg2, ('UNKNOWN', 0))
                        algs_for_zip.append((hash_type, s2))
                        # if alg_zip_best is None:
                        #     if hash_type:
                        #         alg_zip_best = (hash_type,s)
                        #     else:
                        #         print('unsupport alg', alg2)
                        # elif alg_zip_best[0] == 'SHA256' and hash_type== 'SHA512':
                        #     alg_zip_best = (hash_type, s)
                        # else:
                        #     pass
                        # print(s2)
                for certificate in extract_list_by_int_prefix(certificates):
                    # c = decode(certificate,asn1Spec=Certificate())[0]
                    c = x509.Certificate.load(certificate)
                    mycert = cert(c)
                    cert_cache[mycert.fgprint] = mycert
                    if mycert.subjkey:
                        relation_cache[mycert.subjkey] = mycert.fgprint
                    if mycert.pub_key.dump() == public_key_info.dump():
                        verified_certs.append(mycert.fgprint)
                    else:
                        ret = 'v2PubkeyNotCert'
    verified_chains = verify_chain(verified_certs, relation_cache, cert_cache)
    all_certs_with_out_object = {}
    for fgprint, mycert in cert_cache.items():
        all_certs_with_out_object[mycert.fgprint] = mycert.dump()
    return algs_for_zip, verified_chains, all_certs_with_out_object


if __name__ == '__main__':

    for f in [
        'g:/work/8/f45368d392cf31eb0254330b1d80635f~/0b98ff1f8fe0a8aa3681b4d0ab61ccb2~/META-INF/UNICOM.RSA',
        'g:/work/8/f45368d392cf31eb0254330b1d80635f~/TrustTracker.v1.0.8-signed/META-INF/CERT.RSA',
        'g:/work/8/f45368d392cf31eb0254330b1d80635f~/META-INF/CERT.RSA',
        'G:/work/201404/4/1/3a368d197774a280b974baade9fc1756~/META-INF/PIP.DSA',
        'g:/work/201704/5e5b11108bbc431cfe8e9fa8e4b78d0e~\META-INF\AMAL.EC',
    ]:
        import os

        if not os.path.exists(f):
            continue
        print('=' * 79)
        signed_data = open(f, 'rb').read()
        sf_data = open(f.rsplit('.', 1)[0] + '.SF', 'rb').read()
        print(check_sig_v2(signed_data, sf_data))
