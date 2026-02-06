# -*- coding: utf-8 -*-
"""
Constructor de elementos XML para firma XAdES-BES.

Genera los elementos SignedInfo, SignedProperties, KeyInfo según
las especificaciones del SRI Ecuador.
"""

from __future__ import absolute_import, unicode_literals

from datetime import datetime

from lxml import etree

from .constants import (
    NS_DS, NS_ETSI, ALG_C14N, ALG_SHA1, ALG_RSA_SHA1,
    ALG_ENVELOPED, XADES_SIGNED_PROPS
)
from .compat import PY2


class XAdESBuilder(object):
    """
    Constructor de elementos XAdES-BES para firma electrónica.
    """

    def __init__(self, cert_manager, signature_id):
        """
        Inicializa el builder.

        Args:
            cert_manager: Instancia de CertificateManager
            signature_id: ID único para la firma
        """
        self._cert_manager = cert_manager
        self._signature_id = signature_id

    def build_signed_info(self, doc_digest_b64, signed_props_digest_b64, document_ref_id):
        """
        Construye el elemento SignedInfo.

        Args:
            doc_digest_b64: Digest del documento en base64
            signed_props_digest_b64: Digest de SignedProperties en base64
            document_ref_id: ID de referencia del documento

        Returns:
            lxml.etree.Element: Elemento SignedInfo
        """
        signed_info = etree.Element(
            '{{{}}}{}'.format(NS_DS, 'SignedInfo'),
            nsmap={'ds': NS_DS}
        )

        # CanonicalizationMethod
        c14n_method = etree.SubElement(
            signed_info,
            '{{{}}}{}'.format(NS_DS, 'CanonicalizationMethod'),
            attrib={'Algorithm': ALG_C14N}
        )

        # SignatureMethod
        sig_method = etree.SubElement(
            signed_info,
            '{{{}}}{}'.format(NS_DS, 'SignatureMethod'),
            attrib={'Algorithm': ALG_RSA_SHA1}
        )

        # Reference al documento (con transforms)
        ref_doc = etree.SubElement(
            signed_info,
            '{{{}}}{}'.format(NS_DS, 'Reference'),
            attrib={
                'Id': document_ref_id,
                'URI': '#comprobante'
            }
        )

        transforms = etree.SubElement(ref_doc, '{{{}}}{}'.format(NS_DS, 'Transforms'))
        etree.SubElement(
            transforms,
            '{{{}}}{}'.format(NS_DS, 'Transform'),
            attrib={'Algorithm': ALG_ENVELOPED}
        )

        etree.SubElement(
            ref_doc,
            '{{{}}}{}'.format(NS_DS, 'DigestMethod'),
            attrib={'Algorithm': ALG_SHA1}
        )

        digest_value = etree.SubElement(ref_doc, '{{{}}}{}'.format(NS_DS, 'DigestValue'))
        if PY2:
            digest_value.text = doc_digest_b64 if isinstance(doc_digest_b64, unicode) else doc_digest_b64.decode('ascii')
        else:
            digest_value.text = doc_digest_b64 if isinstance(doc_digest_b64, str) else doc_digest_b64.decode('ascii')

        # Reference a SignedProperties
        ref_props = etree.SubElement(
            signed_info,
            '{{{}}}{}'.format(NS_DS, 'Reference'),
            attrib={
                'Type': XADES_SIGNED_PROPS,
                'URI': '#Signature{}-SignedProperties{}'.format(
                    self._signature_id, self._signature_id
                )
            }
        )

        etree.SubElement(
            ref_props,
            '{{{}}}{}'.format(NS_DS, 'DigestMethod'),
            attrib={'Algorithm': ALG_SHA1}
        )

        digest_value_props = etree.SubElement(ref_props, '{{{}}}{}'.format(NS_DS, 'DigestValue'))
        if PY2:
            digest_value_props.text = signed_props_digest_b64 if isinstance(signed_props_digest_b64, unicode) else signed_props_digest_b64.decode('ascii')
        else:
            digest_value_props.text = signed_props_digest_b64 if isinstance(signed_props_digest_b64, str) else signed_props_digest_b64.decode('ascii')

        return signed_info

    def build_signed_properties(self, document_ref_id):
        """
        Construye el elemento SignedProperties.

        Args:
            document_ref_id: ID de referencia del documento

        Returns:
            lxml.etree.Element: Elemento SignedProperties
        """
        # IMPORTANTE: Incluir ambos namespaces desde la creación
        # Esto evita problemas de redistribución de namespaces al insertar
        signed_props = etree.Element(
            '{{{}}}{}'.format(NS_ETSI, 'SignedProperties'),
            attrib={'Id': 'Signature{}-SignedProperties{}'.format(
                self._signature_id, self._signature_id
            )},
            nsmap={'etsi': NS_ETSI, 'ds': NS_DS}
        )

        # SignedSignatureProperties
        signed_sig_props = etree.SubElement(
            signed_props,
            '{{{}}}{}'.format(NS_ETSI, 'SignedSignatureProperties')
        )

        # SigningTime
        signing_time = etree.SubElement(
            signed_sig_props,
            '{{{}}}{}'.format(NS_ETSI, 'SigningTime')
        )
        signing_time.text = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

        # SigningCertificate
        signing_cert = etree.SubElement(
            signed_sig_props,
            '{{{}}}{}'.format(NS_ETSI, 'SigningCertificate')
        )

        cert = etree.SubElement(signing_cert, '{{{}}}{}'.format(NS_ETSI, 'Cert'))

        cert_digest = etree.SubElement(cert, '{{{}}}{}'.format(NS_ETSI, 'CertDigest'))

        etree.SubElement(
            cert_digest,
            '{{{}}}{}'.format(NS_DS, 'DigestMethod'),
            attrib={'Algorithm': ALG_SHA1}
        )

        digest_value = etree.SubElement(cert_digest, '{{{}}}{}'.format(NS_DS, 'DigestValue'))
        cert_digest_value = self._cert_manager.get_certificate_digest_sha1()
        digest_value.text = cert_digest_value

        issuer_serial = etree.SubElement(cert, '{{{}}}{}'.format(NS_ETSI, 'IssuerSerial'))

        x509_issuer = etree.SubElement(issuer_serial, '{{{}}}{}'.format(NS_DS, 'X509IssuerName'))
        x509_issuer.text = self._cert_manager.get_issuer_name()

        x509_serial = etree.SubElement(issuer_serial, '{{{}}}{}'.format(NS_DS, 'X509SerialNumber'))
        x509_serial.text = str(self._cert_manager.get_serial_number())

        # SignedDataObjectProperties
        signed_data_props = etree.SubElement(
            signed_props,
            '{{{}}}{}'.format(NS_ETSI, 'SignedDataObjectProperties')
        )

        data_obj_format = etree.SubElement(
            signed_data_props,
            '{{{}}}{}'.format(NS_ETSI, 'DataObjectFormat'),
            attrib={'ObjectReference': '#{}'.format(document_ref_id)}
        )

        description = etree.SubElement(data_obj_format, '{{{}}}{}'.format(NS_ETSI, 'Description'))
        description.text = 'contenido compance'

        mime_type = etree.SubElement(data_obj_format, '{{{}}}{}'.format(NS_ETSI, 'MimeType'))
        mime_type.text = 'text/xml'

        return signed_props

    def build_key_info(self):
        """
        Construye el elemento KeyInfo.

        Returns:
            lxml.etree.Element: Elemento KeyInfo
        """
        key_info = etree.Element('{{{}}}{}'.format(NS_DS, 'KeyInfo'))

        # X509Data
        x509_data = etree.SubElement(key_info, '{{{}}}{}'.format(NS_DS, 'X509Data'))

        x509_cert = etree.SubElement(x509_data, '{{{}}}{}'.format(NS_DS, 'X509Certificate'))
        x509_cert.text = self._cert_manager.get_certificate_b64()

        # KeyValue
        key_value = etree.SubElement(key_info, '{{{}}}{}'.format(NS_DS, 'KeyValue'))

        rsa_key_value = etree.SubElement(key_value, '{{{}}}{}'.format(NS_DS, 'RSAKeyValue'))

        modulus = etree.SubElement(rsa_key_value, '{{{}}}{}'.format(NS_DS, 'Modulus'))
        modulus.text = self._cert_manager.get_rsa_modulus_b64()

        exponent = etree.SubElement(rsa_key_value, '{{{}}}{}'.format(NS_DS, 'Exponent'))
        exponent.text = self._cert_manager.get_rsa_exponent_b64()

        return key_info