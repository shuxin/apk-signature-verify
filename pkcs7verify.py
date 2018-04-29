#!/usr/bin/python
# coding=utf-8
import binascii
import hashlib
import struct
import math

from asn1crypto import cms, x509
from asn1crypto import algos, keys
from asn1crypto import pem

DEBUG = False

##########################################################################################################################################################################
# DSA RSA ECDSA ( pure python without openssl )
##########################################################################################################################################################################

secp192k1 = dict(
    p = 2**192 - 2**32 - 2**12 - 2**8 - 2**7 - 2**6 - 2**3 - 1,
    a = 0,
    b = 3,
    Gx= 0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7DL,
    Gy= 0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9DL,
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8DL,
)
secp192r1 = dict(
    p = 2**192 - 2**64 - 1,
    a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFCL,
    b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1L,
    Gx= 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012L,
    Gy= 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811L,
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831L,
)
secp224k1 = dict(
    p = 2**224 - 2**32 - 2**12 - 2**11 - 2**9 - 2**7 - 2**4 - 2 - 1,
    a = 0,
    b = 5,
    Gx= 0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45CL,
    Gy= 0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5L,
    n = 0x010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7L,
)
secp224r1 = dict(
    p = 2**224 - 2**96 + 1,
    a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFEL,
    b = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4L,
    Gx= 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21L,
    Gy= 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34L,
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3DL,
)
secp256k1 = dict(
    p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1,
    a = 0,
    b = 7,
    Gx= 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L,
    Gy= 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8L,
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L,
)
secp256r1 = dict(
    p = 2**224 * (2**32 - 1) + 2**192 + 2**96 - 1,
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFCL,
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604BL,
    Gx= 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296L,
    Gy= 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5L,
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551L,
)
secp384r1 = dict(
    p = 2**384 - 2**128 - 2**96 + 2**32 - 1,
    a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFCL,
    b = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEFL,
    Gx= 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7L,
    Gy= 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5FL,
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
)
secp521r1 = dict(
    p = 2**521-1,
    a = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCL,
    b = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00L,
    Gx= 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66L,
    Gy= 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650L,
    n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409L,
)

EC_CURVE = {}

EC_CURVE['1.2.840.10045.3.1.1'] = secp192r1
EC_CURVE['1.3.132.0.33'] = secp224r1
EC_CURVE['1.2.840.10045.3.1.7'] = secp256r1
EC_CURVE['1.3.132.0.34'] = secp384r1
EC_CURVE['1.3.132.0.35'] = secp521r1

EC_CURVE['secp192r1'] = secp192r1
EC_CURVE['secp224r1'] = secp224r1
EC_CURVE['secp256r1'] = secp256r1
EC_CURVE['secp384r1'] = secp384r1
EC_CURVE['secp521r1'] = secp521r1

EC_CURVE['NIST192p'] = secp192r1
EC_CURVE['NIST224p'] = secp224r1
EC_CURVE['NIST256p'] = secp256r1
EC_CURVE['NIST384p'] = secp384r1
EC_CURVE['NIST521p'] = secp521r1

EC_CURVE['1.3.132.0.10'] = secp256k1
EC_CURVE['secp256k1'] = secp256k1

##########################################################################################################################################################################

def bytes_to_long(encoded):
    return reduce(lambda x, y: x * 256 + y, map(ord, encoded))

def _fast_exponentiation(a, p, n):
    result = a % n
    remainders = []
    while p != 1:
        remainders.append(p & 1)
        p = p >> 1
    while remainders:
        rem = remainders.pop()
        result = ((a ** rem) * result ** 2) % n
    return result

def _rsa_decode(enc, mod, exp):
    rr = _fast_exponentiation(enc, exp, mod)
    rt = ""
    while rr > 0:
        rt = chr(rr & 0xFF) + rt
        rr /= 256
    return rt

def _inverse(z, a):
    if z > 0 and z < a and a > 0:
        i = a
        j = z
        y1 = 1
        y2 = 0
        while j > 0:
            q = i / j
            r = i - j * q
            y = y2 - y1 * q
            i, j = j, r
            y2, y1 = y1, y
        if i == 1:
            return y2 % a
    raise Exception('Inverse Error')

def _dsa_verify((p, q, g), pub, H, (r, s)):
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
        # print_("Multiplying %s by %d (e3 = %d):" % (self, other, e3))
        while i > 1:
            result = result.double()
            if (e3 & i) != 0 and (e & i) == 0:
                result = result + self
            if (e3 & i) == 0 and (e & i) != 0:
                result = result + negative_self
            # print_(". . . i = %d, result = %s" % ( i, result ))
            i = i // 2
        return result
    def __rmul__(self, other):
        """Multiply a point by an integer."""
        return self * other
    def __str__(self):
        if self == INFINITY:
            return "infinity"
        return "(%d,%d)" % (self.__x, self.__y)
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

def _ecdsa_verify(ec_curve, ec_key, H, (r, s)):
    n = ec_curve["n"]
    if r < 1 or r > n - 1:
        return False
    if s < 1 or s > n - 1:
        return False
    c = inverse_mod(s, n)
    u1 = (H * c) % n
    u2 = (r * c) % n
    G = ECPoint(
        ec_curve["p"],
        ec_curve["a"],
        ec_curve["b"],
        ec_curve["Gx"],
        ec_curve["Gy"],
        ec_curve["n"])
    point = ECPoint(
        ec_curve["p"],
        ec_curve["a"],
        ec_curve["b"],
        ec_key["x"],
        ec_key["y"])
    xy = G * u1 + point * u2
    v = xy.x() % n
    return v == r

##########################################################################################################################################################################

def sig_hash(signature, public_key_info, fileHashHex):
    fileHash = binascii.a2b_hex(fileHashHex)
    algorithm0 = public_key_info['algorithm']['algorithm'].dotted
    parameters = public_key_info['algorithm']['parameters'].native

    if algorithm0 == "1.2.840.113549.1.1.1":
        mod = public_key_info['public_key'].native['modulus']
        exp = public_key_info['public_key'].native['public_exponent']
        enc = bytes_to_long(signature)
        decoded_sig = _rsa_decode(enc, mod, exp)
        idx = 0
        for byte in decoded_sig:
            if ord(byte) in (0x00, 0x01, 0xff):
                idx += 1
            if ord(byte) == 0x00:
                break
        decoded_bytes = decoded_sig[idx:]
        try:
            v = algos.DigestInfo.load(decoded_bytes)['digest'].native
        except Exception as e:
            v = "fuck"
        # if DEBUG:print binascii.b2a_hex(fileHash), binascii.b2a_hex(v)
        return fileHash == v
    elif algorithm0 == "1.2.840.10040.4.1":
        pub = public_key_info['public_key'].native
        p = parameters['p']
        q = parameters['q']
        g = parameters['g']
        #print encoded
        rs = algos.DSASignature.load(signature)
        r = rs["r"].native
        s = rs["s"].native
        H = bytes_to_long(fileHash)
        return _dsa_verify((p, q, g), pub, H, (r, s))
    elif algorithm0 == "1.2.840.10045.2.1":
        #{iso(1) member-body(2) us(840) ansi-x962(10045) keyType(2) ecPublicKey(1)}
        pubkey = public_key_info['public_key'].native
        certcurve = parameters
        if pubkey[0] != '\x04':
            # POINT_NULL         = (0x00,)
            # POINT_COMPRESSED   = (0x02, 0x03)
            # POINT_UNCOMPRESSED = (0x04,)
            return False
        # import ecdsa
        # from ecdsa.util import sigdecode_der
        # ec = ecdsa.VerifyingKey.from_string(pubkey[1:], curve=ecdsa.NIST256p)
        # ret = ec.verify_digest(signature, fileHash,sigdecode=sigdecode_der)
        # print ret
        ec_curve = EC_CURVE.get(str(certcurve))
        # print ec_curve
        coord_size_p = int(math.ceil(math.log(ec_curve.get("p"), 2) / 8))
        coord_size_n = int(math.ceil(math.log(ec_curve.get("n"), 2) / 8))
        coord_size = coord_size_p# p or n ?
        ec_key = {
            "x":bytes_to_long(pubkey[1:coord_size + 1]),
            "y":bytes_to_long(pubkey[coord_size + 1:]),
        }
        rs = algos.DSASignature.load(signature)
        r = rs["r"].native
        s = rs["s"].native
        H = bytes_to_long(fileHash)
        return _ecdsa_verify(ec_curve, ec_key, H, (r, s))
    else:
        print "unknown algorithm",algorithm0
        return None

#######################################################
#额外处理
#######################################################
class cert():
    def __init__(self, c):
        raw_pem = binascii.b2a_base64(c.dump()).replace("\n", "")
        self.certobj = c
        self.certder = self.certobj.dump()
        self.fgprint = hashlib.sha1(self.certder).hexdigest()
        self.issuer = self.certobj.issuer.human_friendly
        self.subject = self.certobj.subject.human_friendly
        self.certmd5 = hashlib.md5(raw_pem).hexdigest()
        self.certpem = "-----BEGIN CERTIFICATE-----\r\n%s\r\n-----END CERTIFICATE-----\r\n" % '\r\n'.join(raw_pem[pos:pos+64] for pos in xrange(0, len(raw_pem), 64))
        # f = open("%s.crt" % (self.fgprint,),"wb")
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
            pem.armor(u"CERTIFICATE", self.certder),
        )


#验证证书链父子关系(自签根证书，父子均为自身)
def verify_certificate(c, pc):
    # TODO: need a new way
    c_signature_algorithm = c["signature_algorithm"]["algorithm"].dotted
    c_tbs_encoded = c["tbs_certificate"].dump()
    if c_signature_algorithm == "1.2.840.113549.1.1.4":  #RSA
        tbsHashHex = hashlib.md5(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == "1.2.840.113549.1.1.5":
        tbsHashHex = hashlib.sha1(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == "1.2.840.113549.1.1.11":
        tbsHashHex = hashlib.sha256(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == "1.2.840.113549.1.1.12":
        tbsHashHex = hashlib.sha384(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == "1.2.840.113549.1.1.13":
        tbsHashHex = hashlib.sha512(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == "1.2.840.10040.4.3":  #DSA
        tbsHashHex = hashlib.sha1(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == "1.2.840.10045.4.1":  #ecdsa
        tbsHashHex = hashlib.sha1(c_tbs_encoded).hexdigest()
    elif c_signature_algorithm == "1.2.840.10045.4.3.2":
        tbsHashHex = hashlib.sha256(c_tbs_encoded).hexdigest()
    else:
        tbsHashHex = ""
    pub_key = pc.public_key
    return sig_hash(c.signature, pub_key, tbsHashHex)

def verify_chain(verified_certs, relation_cache, cert_cache):
    verified_chains = [] # 完全验证的证书链(二维，没链就仅有自己)
    for chain_head in verified_certs:
        one_verified_chain = []
        one_verified_chain.append(chain_head)
        on_chain = chain_head
        while cert_cache[on_chain].authkey and relation_cache.has_key(cert_cache[on_chain].authkey): # 如果有父证书
            c = on_chain
            pc = relation_cache[cert_cache[on_chain].authkey]
            if c == pc:
                break
            if verify_certificate(cert_cache[c].certobj, cert_cache[pc].certobj):
                one_verified_chain.append(pc) # 附加到链上
            on_chain = pc # 继续验证再父一级正好申诉
        if DEBUG:# 理论上是要验证根证书自签的，Android不需要，Android只是借用证书格式实际上只用公钥部分，ssl必须
            rootca = one_verified_chain[-1]
            self_signed = verify_certificate(cert_cache[rootca].certobj,cert_cache[rootca].certobj)
            if not self_signed:
                continue
        verified_chains.append(one_verified_chain)
    return verified_chains

def return_without_object(cert_cache, verified_chains):
    # 输出纯文本的结果，外部使用不依赖任何证书类
    ver_chain = [] # 输出 pem结构 的 verified_certs
    all_certs = {} # 输出 pem结构 的 cert_cache
    ver_certs = set() # 输出 索引用只有fgprint 的 有效签名证书
    ext_certs = set() # 输出 索引用只有fgprint 的 有效签名证书的父证书
    bad_certs = set() # 输出 索引用只有fgprint 的 无效证书
    for fgprint, mycert in cert_cache.items():
        all_certs[mycert.fgprint] = mycert.dump()
    for one_verified_chain in verified_chains:
        chx = []
        mycert = cert_cache[one_verified_chain[0]]
        ver_certs.add(mycert.fgprint)
        chx.append(mycert.dump())
        for pacert in one_verified_chain[1:]:
            ext_certs.add(pacert)  # 一维list，索引用
            chx.append(pacert.dump())
        ver_chain.append(chx)
    bad_certs = set(all_certs.keys()).difference(ver_certs.union(ext_certs))
    return ver_chain, all_certs, ver_certs, ext_certs, bad_certs

def check_sig(sigbuf="buf of CERT.RSA", sfbuf="buf of CERT.SF"):
    cert_cache = {} # 所有出现的证书
    relation_cache = {} # 记录签发关系
    verified_certs = [] # 完全验证的证书
    sfhash = {
        "1.2.840.113549.2.5": ["MD5", hashlib.md5(sfbuf).hexdigest()],
        "1.3.14.3.2.26": ["SHA1", hashlib.sha1(sfbuf).hexdigest()],
        "2.16.840.1.101.3.4.2.1": ["SHA256", hashlib.sha256(sfbuf).hexdigest()],
        "2.16.840.1.101.3.4.2.2": ["SHA384", hashlib.sha384(sfbuf).hexdigest()],
        "2.16.840.1.101.3.4.2.3": ["SHA512", hashlib.sha512(sfbuf).hexdigest()],
    }
    #"1.2.840.10045.4.3.2":#{iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA2(3) ecdsa-with-SHA256(2)}
    p = cms.ContentInfo.load(sigbuf)
    for c in p['content']['certificates']:
        #print c.raw_der_data
        #print c.tbsCertificate
        #print c.tbsCertificate.pub_key_info.algType
        #print c.tbsCertificate.pub_key_info.key
        mycert = cert(c.chosen)
        test = []
        cert_cache[mycert.fgprint] = mycert
        if mycert.subjkey:
            relation_cache[mycert.subjkey] = mycert.fgprint
        for r in p['content']['signer_infos']:
            #print r.signature
            #print r.digest_algorithm
            #print Hash_Algorithm_OID.get(r.digest_algorithm)
            fileDigest_oid = r['digest_algorithm']['algorithm'].dotted
            fileDigest, fileHash = sfhash.get(fileDigest_oid, ["UNKNOWN", ""])
            v = sig_hash(r['signature'].native, mycert.pub_key, fileHash)
            if v:
                verified_certs.append(mycert.fgprint)
            test = [v, fileDigest, fileHash]
        if DEBUG:
            print "\t*"
            print "\t+" + u'证书指纹:', mycert.fgprint
            print "\t|" + u'签名HASH:', test
            print "\t|" + u'颁发者  :', mycert.issuer
            print "\t|" + u'使用者  :', mycert.subject
            print "\t|" + u'证书链父:', mycert.authkey
            print "\t+" + u'证书链子:', mycert.subjkey
    verified_chains = verify_chain(verified_certs, relation_cache, cert_cache)
    return return_without_object(cert_cache, verified_chains)

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

def check_sig_v2(signedData, signatures, publicKeyBytes):
    cert_cache = {} # 所有出现的证书
    relation_cache = {} # 记录签发关系
    verified_certs = [] # 完全验证的证书
    hashDigestType = {
        0x0101 : "SHA256", #"SHA256withRSA/PSS", "SIGNATURE_RSA_PSS_WITH_SHA256",),
        0x0102 : "SHA512", #"SHA512withRSA/PSS", "SIGNATURE_RSA_PSS_WITH_SHA512",),
        0x0103 : "SHA256", #"SHA256withRSA",      "SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256",),
        0x0104 : "SHA512", #"SHA512withRSA",      "SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512",),
        0x0201 : "SHA256", #"SHA256withECDSA",    "SIGNATURE_ECDSA_WITH_SHA256",),
        0x0202 : "SHA512", #"SHA512withECDSA",    "SIGNATURE_ECDSA_WITH_SHA512",),
        0x0301 : "SHA256", #"SHA256withDSA",      "SIGNATURE_DSA_WITH_SHA256",),
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
    ret = "v2BadCertSig"
    idx = 0
    for signature in extract_list_by_int_prefix(signatures):
        while idx + 8 <= len(signature):
            alg = struct.unpack("L",signature[idx:idx+4])[0]
            i = struct.unpack("L",signature[idx+4:idx+8])[0]
            s = signature[idx+8:idx+8+i]
            idx += 8 + i
            hashtype = hashDigestType.get(alg)
            algs_for_sig.append((hashtype,s))
            if alg_sig_best is None:
                if hashtype:
                    alg_sig_best = (hashtype,s)
                else:
                    print "unsupport alg",alg
            elif alg_sig_best[0] == "SHA256" and hashtype == "SHA512":
                alg_sig_best = (hashtype,s)
            else:
                pass
    if alg_sig_best:
        fileDigest,siginfo = alg_sig_best
        public_key_info = keys.PublicKeyInfo.load(publicKeyBytes)
        sfhash = {
            # "MD5": hashlib.md5(hashs).hexdigest(),
            # "SHA1": hashlib.sha1(hashs).hexdigest(),
            "SHA256": hashlib.sha256(signedData).hexdigest(),
            # "SHA384": hashlib.sha384(signedData).hexdigest(),
            "SHA512": hashlib.sha512(signedData).hexdigest(),
        }
        fileHash = sfhash.get(fileDigest,"")
        v = sig_hash(siginfo, public_key_info, fileHash)
        if not v:
            ret = "v2PubkeySigError"
        else:
            data2 = extract_list_by_int_prefix(signedData)
            if len(data2) >= 2: # ingore additional attributes
                digests, certificates = data2[:2]
                for digest in extract_list_by_int_prefix(digests):
                    idx = 0
                    while idx + 8 <= len(digest):
                        alg2 = struct.unpack("L",digest[idx:idx+4])[0]
                        i2 = struct.unpack("L",digest[idx+4:idx+8])[0]
                        s2 = digest[idx+8:idx+8+i2]
                        idx += 8 + i2
                        hashtype = hashDigestType.get(alg2)
                        algs_for_zip.append((hashtype,s2))
                        # if alg_zip_best is None:
                        #     if hashtype:
                        #         alg_zip_best = (hashtype,s)
                        #     else:
                        #         print "unsupport alg",alg2
                        # elif alg_zip_best[0] == "SHA256" and hashtype== "SHA512":
                        #     alg_zip_best = (hashtype,s)
                        # else:
                        #     pass
                        # print s2
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
                        ret = "v2PubkeyNotCert"
                    if DEBUG:
                        print "\t*"
                        print "\t+" + u'证书指纹:', mycert.fgprint
                        print "\t|" + u'签名HASH:', [v, fileDigest, fileHash]
                        print "\t|" + u'颁发者  :', mycert.issuer
                        print "\t|" + u'使用者  :', mycert.subject
                        print "\t|" + u'证书链父:', mycert.authkey
                        print "\t+" + u'证书链子:', mycert.subjkey
    verified_chains = verify_chain(verified_certs, relation_cache, cert_cache)
    ver_chain, all_certs, ver_certs, ext_certs, bad_certs = return_without_object(cert_cache, verified_chains)
    return ret,algs_for_zip,ver_chain,all_certs,ver_certs,ext_certs,bad_certs

if __name__ == "__main__":

    for f in [
        r"g:\work\8\f45368d392cf31eb0254330b1d80635f~\0b98ff1f8fe0a8aa3681b4d0ab61ccb2~\META-INF\UNICOM.RSA",
        r"g:\work\8\f45368d392cf31eb0254330b1d80635f~\TrustTracker.v1.0.8-signed\META-INF\CERT.RSA",
        r"g:\work\8\f45368d392cf31eb0254330b1d80635f~\META-INF\CERT.RSA",
        r"G:\work\201404\4\1\3a368d197774a280b974baade9fc1756~\META-INF\PIP.DSA",
        r"g:\work\201704\5e5b11108bbc431cfe8e9fa8e4b78d0e~\META-INF\AMAL.EC",
    ]:
        import os
        if not os.path.exists(f):
            continue
        print "=" * 79
        sigdata = open(f, "rb").read()
        sfdata = open(f.rsplit(".",1)[0] + ".SF", "rb").read()
        print check_sig(sigdata, sfdata)
