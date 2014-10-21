#!/usr/bin/python
# coding=utf-8
from pyasn1.type import tag, namedtype, namedval, univ, char, useful
from pyasn1.error import PyAsn1Error
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
import base64
import binascii
import hashlib

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
    "1.2.840.113549.1.9.1": "email",
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
        for name_part in name:
            for attr in name_part:
                type = str(attr.getComponentByPosition(0).getComponentByName('type'))
                value = str(attr.getComponentByPosition(0).getComponentByName('value'))
                typeStr = Name_oid.get(type) or type
                values = self.__attributes.get(typeStr)
                if values is None:
                    self.__attributes[typeStr] = [value]
                else:
                    values.append(value)

    def __str__(self):
        valueStrings = []
        for key in sorted(self.__attributes.keys()):
            values = sorted(self.__attributes.get(key))
            valuesStr = ", ".join(["%s=%s" % (key, value) for value in values])
            valueStrings.append(valuesStr)
        return ", ".join(valueStrings)

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
    _enc = reduce(lambda x, y: x * 256 + y, map(ord, encoded))
    _mod = reduce(lambda x, y: x * 256 + y, map(ord, pub_key["mod"]))
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
    _H = int(fileHash, 16)
    return _verify((_p, _q, _g), _H, _pub, (r, s))


def sig_hash(signature, public_key_info, fileHash):
    algorithm = public_key_info.getComponentByName("algorithm")
    bitstr_key = public_key_info.getComponentByName("subjectPublicKey")
    alg = str(algorithm)
    parameters = algorithm.getComponentByName("parameters")

    if alg == "1.2.840.113549.1.1.1":
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
        try:
            v = binascii.hexlify(decode(decoded_bytes, asn1Spec=DigestInfo())[0].getComponentByName("digest")._value)
        except Exception, e:
            v = ""
        if DEBUG:
            print fileHash, v
        return fileHash == v
    elif alg == "1.2.840.10040.4.1":
        pubkey = bitstr_key.toOctets()
        dsakey = decode(pubkey, asn1Spec=DsaPubKey())[0]
        parameters = decode(parameters, asn1Spec=DssParams())[0]
        paramDict = {"pub": int(dsakey)}
        for param in ['p', 'q', 'g']:
            paramDict[param] = parameters.getComponentByName(param)._value
        key = paramDict
        return _dsa_decode(signature, key, fileHash)
    else:
        return None


#######################################################
#额外处理
#######################################################
class cert():
    def __init__(self, c):
        self.content = c
        self.issuer = str(c.tbsCertificate.issuer)
        self.subject = str(c.tbsCertificate.subject)
        self.certmd5 = hashlib.md5(base64.encodestring(c.raw_der_data).replace("\n", "")).hexdigest()
        self.authkey = None
        self.subjkey = None
        if c.tbsCertificate.authKeyIdExt:
            self.authkey = binascii.hexlify(c.tbsCertificate.authKeyIdExt.value.key_id)
        if c.tbsCertificate.subjKeyIdExt:
            self.subjkey = binascii.hexlify(c.tbsCertificate.subjKeyIdExt.value.subject_key_id)
        self.pub_key = c.tbsCertificate.pub_key_info


#验证证书链父子关系
def verify_certificate(c, cc):
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
    sfhash = {
        "1.2.840.113549.2.5": ["MD5", hashlib.md5(sfbuf).hexdigest()],
        "1.3.14.3.2.26": ["SHA1", hashlib.sha1(sfbuf).hexdigest()],
        "2.16.840.1.101.3.4.2.1": ["SHA256", hashlib.sha256(sfbuf).hexdigest()],
        "2.16.840.1.101.3.4.2.2": ["SHA384", hashlib.sha384(sfbuf).hexdigest()],
        "2.16.840.1.101.3.4.2.3": ["SHA512", hashlib.sha512(sfbuf).hexdigest()],
    }
    certs = {}
    cert_chain = {}
    verified_chain = []
    verified_certs = []
    p = PKCS7_SignedData(sigbuf)
    for c in p.certificates:
        #print c.raw_der_data
        #print c.tbsCertificate
        #print c.tbsCertificate.pub_key_info.algType
        #print c.tbsCertificate.pub_key_info.key
        mycert = cert(c)
        test = []
        certs[mycert.certmd5] = mycert
        if mycert.subjkey:
            cert_chain[mycert.subjkey] = mycert.certmd5
        for r in p.signerInfos:
            #print r.signature
            #print r.digest_algorithm
            #print Hash_Algorithm_OID.get(r.digest_algorithm)
            e, fileHash = sfhash.get(r.digest_algorithm, ["UNKNOWN", ""])
            v = sig_hash(r.signature, mycert.pub_key, fileHash)
            if v:
                verified_chain.append([mycert.certmd5])
                verified_certs.append([mycert.certmd5, e, fileHash])
            test = [v, e, fileHash]
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
            onebase = cc
    if DEBUG:
        print verified_certs
        print verified_chain
    ret = []
    for ch in verified_chain:
        chx = []
        for c in ch:
            chx.append([c, certs[c].subject, certs[c].issuer])
        ret.append(chx)
    return ret


if __name__ == "__main__":

    for f in [
        r"g:\work\8\f45368d392cf31eb0254330b1d80635f~\0b98ff1f8fe0a8aa3681b4d0ab61ccb2~\META-INF\UNICOM.RSA",
        r"g:\work\8\f45368d392cf31eb0254330b1d80635f~\TrustTracker.v1.0.8-signed\META-INF\CERT.RSA",
        r"g:\work\8\f45368d392cf31eb0254330b1d80635f~\META-INF\CERT.RSA",
        r"G:\work\201404\4\1\3a368d197774a280b974baade9fc1756~\META-INF\PIP.DSA",
    ]:
        print "=" * 79
        sigdata = open(f, "rb").read()
        sfdata = open(f[:-3] + "SF", "rb").read()
        print check_sig(sigdata, sfdata)
