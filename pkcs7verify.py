#!/usr/bin/python
# coding=utf-8
import binascii
import hashlib
import struct
import math

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.error import PyAsn1Error
from pyasn1.type import tag, namedtype, namedval, univ, char, useful

DEBUG = False

oid_map = {
    "1.2.840.113549.2.5": "MD5",
    "1.3.14.3.2.26": "SHA-1",
    "2.16.840.1.101.3.4.2.1": "SHA-256",
    "2.16.840.1.101.3.4.2.2": "SHA-384",
    "2.16.840.1.101.3.4.2.3": "SHA-512",
    "1.2.840.113549.1.7.1": "data",
    "1.2.840.113549.1.7.2": "signedData",
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.2": "MD2/RSA",
    "1.2.840.113549.1.1.3": "MD4/RSA",
    "1.2.840.113549.1.1.4": "MD5/RSA",
    "1.2.840.113549.1.1.5": "SHA1/RSA",
    "1.2.840.113549.1.1.11": "SHA256/RSA",
    "1.2.840.113549.1.1.12": "SHA384/RSA",
    "1.2.840.113549.1.1.13": "SHA512/RSA",

    "1.2.840.10040.4.1": "DSA",
    "1.2.840.10040.4.3": "SHA1/DSA",

    "2.5.4.6": "id-at-countryName",
    "2.5.4.10": "id-at-organizationName ",
    "2.5.4.3": "id-at-commonName",
    "2.5.4.11": "id-at-organizationalUnitName",

    "2.5.29.17": "id-ce-subjectAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.32": "Certificate policies",
    "1.3.6.1.5.5.7.1.3": "id-pe-qcStatements",
    "2.5.29.15": "id-ce-keyUsage",
    "2.5.29.14": "id-ce-subjectKeyIdentifier ",
    "2.5.29.31": "id-ce-CRLDistributionPoints ",
    "2.5.29.35": "id-ce-authorityKeyIdentifier ",

    "2.5.29.20": "CRL Number",
    "2.5.29.21": "Reason Code",
    "2.5.29.24": "Invalidity Data",

    "1.2.840.113549.1.9.3": "contentType",
    "1.2.840.113549.1.9.4": "messageDigest",
    "1.2.840.113549.1.9.5": "Signing Time"
}
Name_oid = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.45": "X500UID",
    "1.2.840.113549.1.9.1": "emailAddress",
    "2.5.4.17": "zip",
    "2.5.4.9": "street",
    "2.5.4.15": "businessCategory",
    "2.5.4.5": "serialNumber",
    "2.5.4.43": "initials",
    "2.5.4.44": "generationQualifier",
    "2.5.4.4": "surname",
    "2.5.4.42": "givenName",
    "2.5.4.12": "title",
    "2.5.4.46": "dnQualifier",
    "2.5.4.65": "pseudonym",
    "0.9.2342.19200300.100.1.25": "DC",
    #
    "1.3.6.1.4.1.5734.1.2": "Apellido1",
    "1.3.6.1.4.1.5734.1.3": "Apellido2",
    "1.3.6.1.4.1.5734.1.1": "Nombre",
    "1.3.6.1.4.1.5734.1.4": "DNI",
    #
    "0.9.2342.19200300.100.1.1": "Userid",
    #
    "2.16.724.1.3.5.2.2.1": "certType",
    "2.16.724.1.3.5.2.2.2": "O",
    "2.16.724.1.3.5.2.2.3": "serialNumber",
    "2.16.724.1.3.5.2.2.4": "DNI",
    "2.16.724.1.3.5.2.2.5": "CN",
    "2.16.724.1.3.5.2.2.6": "Nombre",
    "2.16.724.1.3.5.2.2.7": "Apellido1",
    "2.16.724.1.3.5.2.2.8": "Apellido2",
    "2.16.724.1.3.5.2.2.9": "email",
}
Attribute_oid = {
    "1.2.840.113549.1.9.1": "emailAddress",
    "1.2.840.113549.1.9.2": "unstructuredName",
    "1.2.840.113549.1.9.3": "contentType",
    "1.2.840.113549.1.9.4": "messageDigest",
    "1.2.840.113549.1.9.5": "signingTime",
    "1.2.840.113549.1.9.6": "counterSignature",
    "1.2.840.113549.1.9.7": "challengePassword",
    "1.2.840.113549.1.9.8": "unstructuredAddress",
    "1.2.840.113549.1.9.16.2.12": "signingCertificate",
    "2.5.4.5": "serialNumber",
}
ContentType_oid = {
    "1.2.840.113549.1.7.1": "data",
    "1.2.840.113549.1.7.2": "signedData",
    "1.2.840.113549.1.7.3": "envelopedData",
    "1.2.840.113549.1.7.4": "signedAndEnvelopedData",
    "1.2.840.113549.1.7.5": "digestedData",
    "1.2.840.113549.1.7.6": "encryptedData",
    "1.2.840.113549.1.9.16.1.4": "TimeStampToken",
}
ExtendedKeyUsageExt_oid = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.5": "ipsecEndSystem",
    "1.3.6.1.5.5.7.3.6": "ipsecTunnel",
    "1.3.6.1.5.5.7.3.7": "ipsecUser",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
}

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

class Modulus(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x02)
    )


class RsaPubKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("modulus", Modulus()),
        namedtype.NamedType("exp", univ.Integer())
    )

class DsaPubKey(univ.Integer):
    pass

class DssParams(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("p", univ.Integer()),
        namedtype.NamedType("q", univ.Integer()),
        namedtype.NamedType("g", univ.Integer()),
    )

class Dss_Sig_Value(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),
        namedtype.NamedType('s', univ.Integer())
    )

class ConvertibleBitString(univ.BitString):
    def toOctets(self):
        def _tuple_to_byte(tuple):
            return chr(int(''.join(map(str, tuple)), 2))

        res = ''
        byte_len = len(self._value) / 8
        for byte_idx in xrange(byte_len):
            bit_idx = byte_idx * 8
            byte_tuple = self._value[bit_idx:bit_idx + 8]
            byte = _tuple_to_byte(byte_tuple)
            res += byte
        return res


class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('teletexString', char.TeletexString()),
        namedtype.NamedType('printableString', char.PrintableString()),
        namedtype.NamedType('universalString', char.UniversalString()),
        namedtype.NamedType('utf8String', char.UTF8String()),
        namedtype.NamedType('bmpString', char.BMPString()),
        namedtype.NamedType('ia5String', char.IA5String()),
        # namedtype.NamedType('gString', univ.OctetString())
        namedtype.NamedType('bitString', univ.BitString()),  # needed for X500 Unique Identifier, RFC 4519
    )

    def __repr__(self):
        try:
            c = self.getComponent()
            return c.__str__()
        except:
            return "Choice type not chosen"

    def __str__(self):
        return repr(self)


class AttributeValue(DirectoryString): pass


class AttributeType(univ.ObjectIdentifier):
    def __str__(self):
        return univ.ObjectIdentifier().prettyOut(self._value)


class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('value', AttributeValue())
    )

    def __repr__(self):
        # s = "%s => %s" % [ self.getComponentByName('type'), self.getComponentByName('value')]
        type = self.getComponentByName('type')
        value = self.getComponentByName('value')
        s = "%s => %s" % (type, value)
        return s

    def __str__(self):
        return self.__repr__()


class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

    def __str__(self):
        buf = ''
        for component in self._componentValues:
            buf += str(component)
            buf += ','
        buf = buf[:len(buf) - 1]
        return buf


class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()

    def __str__(self):
        buf = ''
        for component in self._componentValues:
            buf += str(component)
            buf += ','
        buf = buf[:len(buf) - 1]
        return buf


class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('', RDNSequence())
    )

    def __str__(self):
        return str(self.getComponent())


class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
        # namedtype.OptionalNamedType('parameters', univ.Null())
        # namedtype.OptionalNamedType('parameters', univ.ObjectIdentifier())
    )

    def __repr__(self):
        tuple_oid = self.getComponentByName('algorithm')
        str_oid = univ.ObjectIdentifier().prettyOut(tuple_oid)
        return str_oid

    def __str__(self):
        return repr(self)


class UniqueIdentifier(ConvertibleBitString):
    pass


class DigestInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("digestAgorithm", AlgorithmIdentifier()),
        namedtype.NamedType("digest", univ.OctetString())
    )


class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
        namedtype.NamedType('extnValue', univ.OctetString())
        # namedtype.NamedType('extnValue', ExtensionValue())
    )


class Extensions(univ.SequenceOf):
    componentType = Extension()
    sizeSpec = univ.SequenceOf.sizeSpec


class SubjectPublicKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.NamedType('subjectPublicKey', ConvertibleBitString())
    )


class Time(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('utcTime', useful.UTCTime()),
        namedtype.NamedType('generalTime', useful.GeneralizedTime())
    )

    def __str__(self):
        return str(self.getComponent())


class Validity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('notBefore', Time()),
        namedtype.NamedType('notAfter', Time())
    )


class CertificateSerialNumber(univ.Integer): pass


class Version(univ.Integer):
    namedValues = namedval.NamedValues(
        ('v1', 0), ('v2', 1), ('v3', 2)
    )


class TBSCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', Version('v1', tagSet=Version.tagSet.tagExplicitly(
            tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))),
        namedtype.NamedType('serialNumber', CertificateSerialNumber()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', Name()),
        namedtype.NamedType('validity', Validity()),
        namedtype.NamedType('subject', Name()),
        namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType('issuerUniqueID', UniqueIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('subjectUniqueID', UniqueIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('extensions', Extensions().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)))
    )


class Certificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertificate', TBSCertificate()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', ConvertibleBitString())
    )


class Certificates(univ.SetOf):
    componentType = Certificate()


class AttributeCertificateV2(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("sigAlg", AlgorithmIdentifier()),
        namedtype.NamedType("signature", ConvertibleBitString())
    )


class CertificateChoices(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("certificate", Certificate()),
    )


class CertificateSet(univ.SetOf):
    componentType = CertificateChoices()


class SignedContent(univ.SequenceOf):
    componentType = univ.OctetString()
    tagSet = univ.SequenceOf.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatConstructed, 0x04)
    )


class Content(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("content_type", univ.ObjectIdentifier()),
        namedtype.NamedType("signed_content", SignedContent(). \
                            subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0)))
    )


class AlgIdentifiers(univ.SetOf):
    componentType = AlgorithmIdentifier()


class SignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("digestAlgs", AlgIdentifiers()),
        namedtype.NamedType("content", Content())
    )


class MsgType(univ.ObjectIdentifier): pass


class SignVersion(univ.Integer): pass


class IssuerAndSerial(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("issuer", Name()),
        namedtype.NamedType("serialNumber", univ.Integer())
    )


class AuthAttributeValue(univ.SetOf):
    def __str__(self):
        return str(self.getComponentByPosition(0))


class AuthAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', AuthAttributeValue())
    )


class Attributes(univ.SetOf):
    componentType = AuthAttribute()


class SignerInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", SignVersion()),
        namedtype.NamedType("issuerAndSerialNum", IssuerAndSerial()),
        namedtype.NamedType("digestAlg", AlgorithmIdentifier()),
        namedtype.OptionalNamedType("authAttributes", Attributes(). \
                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))),
        namedtype.NamedType("encryptAlg", AlgorithmIdentifier()),
        namedtype.NamedType("signature", univ.OctetString()),
        namedtype.OptionalNamedType("unauthAttributes", Attributes(). \
                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1)))
    )


class SignerInfos(univ.SetOf):
    componentType = SignerInfo()


class Crl(univ.Sequence):
    pass


class Crls(univ.Set):
    componentType = Crl()


class V1Content(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("digestAlgs", AlgIdentifiers()),
        namedtype.NamedType("content", Content()),
        namedtype.OptionalNamedType("certificates", Certificates(). \
                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))),
        namedtype.OptionalNamedType("crls", Crls(). \
                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))),
        namedtype.NamedType("signerInfos", SignerInfos())
    )


class Message(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", MsgType()),
        namedtype.NamedType("content", V1Content(). \
                            subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0)))
    )


class EncapsulatedContent(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("eContentType", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("eContent", univ.OctetString(). \
                                    subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))),

    )


class QtsContent(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("digestAlgorithms", AlgIdentifiers()),
        namedtype.NamedType("encapsulatedContentInfo", EncapsulatedContent()),
        namedtype.OptionalNamedType("certificates", CertificateSet(). \
                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))),
        namedtype.OptionalNamedType("crls", Crls(). \
                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))),
        namedtype.NamedType("signerInfos", SignerInfos()),
    )


class Qts(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", MsgType()),
        namedtype.NamedType("content", QtsContent(). \
                            subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0)))
    )


class IssuerName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("name", RDNSequence().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x4))),
    )


class SubjectKeyId(univ.OctetString):
    pass


class KeyId(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("keyIdentifier", univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))),
        namedtype.OptionalNamedType("authorityCertIssuer", IssuerName().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))),
        namedtype.OptionalNamedType("authorityCertSerialNum", univ.Integer().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x2))),
    )


# ######################################################
# PKCS7
#######################################################
class PKCS7_Name():
    def __init__(self, name):
        self.__attributes = {}
        self.attributes_sorted = []
        for name_part in name:
            for attr in name_part:
                type = str(attr.getComponentByPosition(0).getComponentByName('type'))
                value = str(attr.getComponentByPosition(0).getComponentByName('value'))
                typeStr = Name_oid.get(type) or type
                values = self.__attributes.get(typeStr)
                if values is None:
                    #print type, typeStr
                    self.__attributes[typeStr] = [value]
                    self.attributes_sorted.append(typeStr)
                else:
                    values.append(value)

    def __str__(self):
        valueStrings = []
        #print self.__attributes.keys()
        for key in self.attributes_sorted:#sorted(self.__attributes.keys()):
            values = sorted(self.__attributes.get(key))
            valuesStr = ", ".join(["%s=%s" % (key, value) for value in values])
            valueStrings.append(valuesStr)
        #print ", ".join(valueStrings)
        return "/".join(valueStrings)

    def get_attributes(self):
        return self.__attributes.copy()


class PKCS7_AuthorityKeyIdExt():
    def __init__(self, asn1_authKeyId):
        if (asn1_authKeyId.getComponentByName("keyIdentifier")) is not None:
            self.key_id = asn1_authKeyId.getComponentByName("keyIdentifier")._value
        if (asn1_authKeyId.getComponentByName("authorityCertSerialNum")) is not None:
            self.auth_cert_sn = asn1_authKeyId.getComponentByName("authorityCertSerialNum")._value
        if (asn1_authKeyId.getComponentByName("authorityCertIssuer")) is not None:
            issuer = asn1_authKeyId.getComponentByName("authorityCertIssuer")
            iss = str(issuer.getComponentByName("name"))
            self.auth_cert_issuer = iss


class PKCS7_SubjectKeyIdExt():
    def __init__(self, asn1_subKey):
        self.subject_key_id = asn1_subKey._value


class PKCS7_Extension():
    _extensionDecoders = {
        "2.5.29.35": (KeyId(), lambda v: PKCS7_AuthorityKeyIdExt(v), "authKeyIdExt"),
        "2.5.29.14": (SubjectKeyId(), lambda v: PKCS7_SubjectKeyIdExt(v), "subjKeyIdExt"),
    }

    def __init__(self, extension):
        self.id = univ.ObjectIdentifier().prettyOut(extension.getComponentByName("extnID"))
        self.ext_type = None
        self.value = extension.getComponentByName("extnValue")._value
        decoderTuple = PKCS7_Extension._extensionDecoders.get(self.id)
        if decoderTuple is not None:
            try:
                (decoderAsn1Spec, decoderFunction, extType) = decoderTuple
                v = decode(self.value, asn1Spec=decoderAsn1Spec)[0]
                self.value = decoderFunction(v)
                self.ext_type = extType
            except PyAsn1Error:
                pass


class PKCS7_Certificate():
    def __init__(self, tbsCertificate):
        self.version = tbsCertificate.getComponentByName("version")._value
        self.serial_number = tbsCertificate.getComponentByName("serialNumber")._value
        self.signature_algorithm = str(tbsCertificate.getComponentByName("signature"))
        self.issuer = PKCS7_Name(tbsCertificate.getComponentByName("issuer"))
        self.subject = PKCS7_Name(tbsCertificate.getComponentByName("subject"))
        self.pub_key_info = tbsCertificate.getComponentByName("subjectPublicKeyInfo")
        issuer_uid = tbsCertificate.getComponentByName("issuerUniqueID")
        if issuer_uid:
            self.issuer_uid = issuer_uid.toOctets()
        else:
            self.issuer_uid = None
        subject_uid = tbsCertificate.getComponentByName("subjectUniqueID")
        if subject_uid:
            self.subject_uid = subject_uid.toOctets()
        else:
            self.subject_uid = None
        extensions = tbsCertificate.getComponentByName('extensions')
        if extensions:
            self.extensions = [PKCS7_Extension(ext) for ext in extensions]
        else:
            self.extensions = []
        #make known extensions accessible through attributes
        for extAttrName in ["authKeyIdExt", "subjKeyIdExt"]:
            setattr(self, extAttrName, None)
        for ext in self.extensions:
            if ext.ext_type:
                setattr(self, ext.ext_type, ext)


class PKCS7_X509Certificate():
    def __init__(self, certificate):
        self.signature_algorithm = str(certificate.getComponentByName("signatureAlgorithm"))
        self.signature = certificate.getComponentByName("signatureValue").toOctets()
        self.tbs = certificate.getComponentByName("tbsCertificate")
        self.tbsCertificate = PKCS7_Certificate(certificate.getComponentByName("tbsCertificate"))
        self.raw_der_data = encode(certificate)
        self.tbs_encoded = encode(self.tbs)


class PKCS7_SignerInfo():
    def __init__(self, signer_info):
        self.version = signer_info.getComponentByName("version")._value
        self.issuer = PKCS7_Name(signer_info.getComponentByName("issuerAndSerialNum").getComponentByName("issuer"))
        self.serial_number = signer_info.getComponentByName("issuerAndSerialNum").getComponentByName(
            "serialNumber")._value
        self.digest_algorithm = str(signer_info.getComponentByName("digestAlg"))
        self.encrypt_algorithm = str(signer_info.getComponentByName("encryptAlg"))
        self.signature = signer_info.getComponentByName("signature")._value


class PKCS7_SignedData():
    def __init__(self, parsed_content):
        contentType, content = decode(parsed_content, asn1Spec=Qts())[0]
        if str(contentType) != "1.2.840.113549.1.7.2":
            raise ValueError("Currently we only can handle PKCS7 'signedData' messages")
        version, digestAlgorithms, encapsulatedContentInfo, certificates, crls, signerInfos = content
        self.certificates = [PKCS7_X509Certificate(cert[0]) for cert in certificates]
        self.signerInfos = [PKCS7_SignerInfo(info) for info in signerInfos]


#######################################################
#DSA RSA 算法
#######################################################

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


def _rsa_decode(encoded, pub_key):
    _enc = bytes_to_long(encoded)
    _mod = bytes_to_long(pub_key["mod"])
    _exp = pub_key["exp"]
    rr = _fast_exponentiation(_enc, _exp, _mod)
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


def _verify((p, q, g), H, y, (r, s)):
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    w = _inverse(s, q)
    u1, u2 = (H * w) % q, (r * w) % q
    v1 = pow(g, u1, p)
    v2 = pow(y, u2, p)
    v = ((v1 * v2) % p)
    v = v % q
    return v == r


def _dsa_decode(encoded, pub_key, fileHash):
    #print encoded
    rs = decode(encoded, asn1Spec=Dss_Sig_Value())[0]
    r = rs.getComponentByName("r")._value
    s = rs.getComponentByName("s")._value
    _p = pub_key["p"]
    _q = pub_key["q"]
    _g = pub_key["g"]
    _pub = pub_key["pub"]
    _H = bytes_to_long(fileHash)
    return _verify((_p, _q, _g), _H, _pub, (r, s))

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

def _ecdsa_decode(encoded, ec_curve, ec_key, fileHash):
    rs = decode(encoded, asn1Spec=Dss_Sig_Value())[0]
    r = rs.getComponentByName("r")._value
    s = rs.getComponentByName("s")._value
    n = ec_curve["n"]
    if r < 1 or r > n - 1:
        return False
    if s < 1 or s > n - 1:
        return False
    c = inverse_mod(s, n)
    u1 = (bytes_to_long(fileHash) * c) % n
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


def sig_hash(signature, public_key_info, fileHashHex):
    fileHash = binascii.a2b_hex(fileHashHex)
    algorithm = public_key_info.getComponentByName("algorithm")
    bitstr_key = public_key_info.getComponentByName("subjectPublicKey")
    algorithm0 = algorithm.getComponentByName("algorithm")
    parameters = algorithm.getComponentByName("parameters")

    if algorithm0 == univ.ObjectIdentifier("1.2.840.113549.1.1.1"):
        pubkey = bitstr_key.toOctets()
        rsakey = decode(pubkey, asn1Spec=RsaPubKey())[0]
        mod = rsakey.getComponentByName("modulus")._value
        exp = rsakey.getComponentByName("exp")._value
        key = {'mod': mod, 'exp': exp}
        decoded_sig = _rsa_decode(signature, key)
        idx = 0
        for byte in decoded_sig:
            if ord(byte) in (0x00, 0x01, 0xff):
                idx += 1
            if ord(byte) == 0x00:
                break
        decoded_bytes = decoded_sig[idx:]
        v = decode(decoded_bytes, asn1Spec=DigestInfo())[0].getComponentByName("digest")._value
        # if DEBUG:print binascii.b2a_hex(fileHash), binascii.b2a_hex(v)
        return fileHash == v
    elif algorithm0 == univ.ObjectIdentifier("1.2.840.10040.4.1"):
        pubkey = bitstr_key.toOctets()
        dsakey = decode(pubkey, asn1Spec=DsaPubKey())[0]
        parameters = decode(parameters, asn1Spec=DssParams())[0]
        paramDict = {"pub": int(dsakey)}
        for param in ['p', 'q', 'g']:
            paramDict[param] = parameters.getComponentByName(param)._value
        key = paramDict
        return _dsa_decode(signature, key, fileHash)
    elif algorithm0 == univ.ObjectIdentifier("1.2.840.10045.2.1"):
        #{iso(1) member-body(2) us(840) ansi-x962(10045) keyType(2) ecPublicKey(1)}
        pubkey = bitstr_key.toOctets()
        certcurve = decode(parameters.asOctets())[0]
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
        return _ecdsa_decode(signature, ec_curve, ec_key, fileHash)
    else:
        print "unknown algorithm",algorithm0
        return None

#######################################################
#额外处理
#######################################################
class cert():
    def __init__(self, c):
        raw_sig = binascii.b2a_base64(c.raw_der_data).replace("\n","")
        self.content = c
        self.issuer = str(c.tbsCertificate.issuer)
        self.subject = str(c.tbsCertificate.subject)
        self.certmd5 = hashlib.md5(raw_sig).hexdigest()
        self.certbuf = "-----BEGIN CERTIFICATE-----\r\n%s\r\n-----END CERTIFICATE-----\r\n" % '\r\n'.join(raw_sig[pos:pos+64] for pos in xrange(0, len(raw_sig), 64))
        self.authkey = None
        self.subjkey = None
        if c.tbsCertificate.authKeyIdExt:
            self.authkey = binascii.b2a_hex(c.tbsCertificate.authKeyIdExt.value.key_id)
        if c.tbsCertificate.subjKeyIdExt:
            self.subjkey = binascii.b2a_hex(c.tbsCertificate.subjKeyIdExt.value.subject_key_id)
        self.pub_key = c.tbsCertificate.pub_key_info


#验证证书链父子关系
def verify_certificate(c, cc):
    # TODO: need a new way
    if c.signature_algorithm == "1.2.840.113549.1.1.4":  #RSA
        calculated_digest = hashlib.md5(c.tbs_encoded).hexdigest()
    elif c.signature_algorithm == "1.2.840.113549.1.1.5":
        calculated_digest = hashlib.sha1(c.tbs_encoded).hexdigest()
    elif c.signature_algorithm == "1.2.840.113549.1.1.11":
        calculated_digest = hashlib.sha256(c.tbs_encoded).hexdigest()
    elif c.signature_algorithm == "1.2.840.113549.1.1.12":
        calculated_digest = hashlib.sha384(c.tbs_encoded).hexdigest()
    elif c.signature_algorithm == "1.2.840.113549.1.1.13":
        calculated_digest = hashlib.sha512(c.tbs_encoded).hexdigest()
    elif c.signature_algorithm == "1.2.840.10040.4.3":  #DSA
        calculated_digest = hashlib.sha1(c.tbs_encoded).hexdigest()
    else:
        calculated_digest = ""
    pub_key = cc.tbsCertificate.pub_key_info
    return sig_hash(c.signature, pub_key, calculated_digest)


def check_sig(sigbuf="buf of CERT.RSA", sfbuf="buf of CERT.SF"):
    ver_chain = []
    all_certs = {}
    ver_certs = set()
    ext_certs = set()
    bad_certs = set()
    certs = {}
    cert_chain = {}
    verified_chain = []
    sfhash = {
        "1.2.840.113549.2.5": ["MD5", hashlib.md5(sfbuf).hexdigest()],
        "1.3.14.3.2.26": ["SHA1", hashlib.sha1(sfbuf).hexdigest()],
        "2.16.840.1.101.3.4.2.1": ["SHA256", hashlib.sha256(sfbuf).hexdigest()],
        "2.16.840.1.101.3.4.2.2": ["SHA384", hashlib.sha384(sfbuf).hexdigest()],
        "2.16.840.1.101.3.4.2.3": ["SHA512", hashlib.sha512(sfbuf).hexdigest()],
    }
    #"1.2.840.10045.4.3.2":#{iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA2(3) ecdsa-with-SHA256(2)}
    p = PKCS7_SignedData(sigbuf)
    for c in p.certificates:
        #print c.raw_der_data
        #print c.tbsCertificate
        #print c.tbsCertificate.pub_key_info.algType
        #print c.tbsCertificate.pub_key_info.key
        mycert = cert(c)
        test = []
        certs[mycert.certmd5] = mycert
        all_certs[mycert.certmd5] = [mycert.certmd5, mycert.subject, mycert.issuer]
        if mycert.subjkey:
            cert_chain[mycert.subjkey] = mycert.certmd5
        for r in p.signerInfos:
            #print r.signature
            #print r.digest_algorithm
            #print Hash_Algorithm_OID.get(r.digest_algorithm)
            fileDigest, fileHash = sfhash.get(r.digest_algorithm, ["UNKNOWN", ""])
            v = sig_hash(r.signature, mycert.pub_key, fileHash)
            if v:
                verified_chain.append([mycert.certmd5])
                ver_certs.add(mycert.certmd5)
            test = [v, fileDigest, fileHash]
        if DEBUG:
            print u'证书MD5 :', mycert.certmd5
            print u'签名HASH:', test
            print u'颁发者  :', mycert.issuer
            print u'使用者  :', mycert.subject
            print u'证书链父:', mycert.authkey
            print u'证书链子:', mycert.subjkey
            print "-" * 79
    for onechain in verified_chain:
        onebase = onechain[0]
        while certs[onebase].authkey and cert_chain.has_key(certs[onebase].authkey):
            c = onebase
            cc = cert_chain[certs[onebase].authkey]
            if c == cc:
                break
            if verify_certificate(certs[c].content, certs[cc].content):
                onechain.append(cc)
                ext_certs.add(cc)
            onebase = cc
    for ch in verified_chain:
        chx = []
        for c in ch:
            chx.append([c, certs[c].subject, certs[c].issuer, certs[c].certbuf])
        ver_chain.append(chx)
    bad_certs = set(all_certs.keys()).difference(ver_certs.union(ext_certs))
    return ver_chain,all_certs,ver_certs,ext_certs,bad_certs

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
    ver_chain = []
    all_certs = {}
    ver_certs = set()
    ext_certs = set()
    bad_certs = set()
    certs = {}
    cert_chain = {}
    verified_chain = []
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
        public_key_info = decode(publicKeyBytes,asn1Spec=SubjectPublicKeyInfo())[0]
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
                    c = PKCS7_X509Certificate(decode(certificate,asn1Spec=Certificate())[0])
                    mycert = cert(c)
                    certs[mycert.certmd5] = mycert
                    all_certs[mycert.certmd5] = [mycert.certmd5, mycert.subject, mycert.issuer]
                    if mycert.subjkey:
                        cert_chain[mycert.subjkey] = mycert.certmd5
                    if encode(mycert.pub_key) == publicKeyBytes:
                        verified_chain.append([mycert.certmd5])
                        ver_certs.add(mycert.certmd5)
                    else:
                        ret = "v2PubkeyNotCert"
                    if DEBUG:
                        print u'证书MD5 :', mycert.certmd5
                        print u'签名HASH:', [v, fileDigest, fileHash]
                        print u'颁发者  :', mycert.issuer
                        print u'使用者  :', mycert.subject
                        print u'证书链父:', mycert.authkey
                        print u'证书链子:', mycert.subjkey
                        print "-" * 79
    for onechain in verified_chain:
        onebase = onechain[0]
        while certs[onebase].authkey and cert_chain.has_key(certs[onebase].authkey):
            c = onebase
            cc = cert_chain[certs[onebase].authkey]
            if c == cc:
                break
            if verify_certificate(certs[c].content, certs[cc].content):
                onechain.append(cc)
                ext_certs.add(cc)
            onebase = cc
    for ch in verified_chain:
        chx = []
        for c in ch:
            chx.append([c, certs[c].subject, certs[c].issuer, certs[c].certbuf])
        ver_chain.append(chx)
    bad_certs = set(all_certs.keys()).difference(ver_certs.union(ext_certs))
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
