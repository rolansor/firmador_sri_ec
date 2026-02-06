# -*- coding: utf-8 -*-
"""
Firmador XAdES-BES nativo en Python.

Implementa firma digital XAdES-BES según especificaciones del SRI Ecuador:
- Tipo: ENVELOPED
- Algoritmo: RSA-SHA1
- Hash: SHA-1
- C14N: http://www.w3.org/TR/2001/REC-xml-c14n-20010315
- Esquema XAdES: 1.3.2
"""

from __future__ import absolute_import, unicode_literals

import base64
import hashlib
import random

from lxml import etree

from .certificate import CertificateManager
from .canonicalization import canonicalize
from .xml_builder import XAdESBuilder
from .constants import NS_DS, NS_ETSI
from .compat import ensure_bytes, PY2


class XAdESSigner(object):
    """
    Firmador XAdES-BES nativo para comprobantes electrónicos del SRI Ecuador.
    """

    def __init__(self, p12_path, password):
        """
        Inicializa el firmador con el certificado PKCS12.

        Args:
            p12_path: Ruta al archivo .p12
            password: Clave del certificado
        """
        self._cert_manager = CertificateManager(p12_path, password)

    def sign(self, xml_document):
        """
        Firma un documento XML con XAdES-BES.

        El documento debe tener un elemento raíz con id="comprobante".

        Args:
            xml_document: XML del comprobante (string o bytes)

        Returns:
            bytes: XML firmado
        """
        # Asegurar que sea bytes
        xml_bytes = ensure_bytes(xml_document)

        # IMPORTANTE: Normalizar line endings a LF (Windows usa CRLF)
        xml_bytes = xml_bytes.replace(b'\r\n', b'\n').replace(b'\r', b'\n')

        # Parsear el documento XML
        parser = etree.XMLParser(remove_blank_text=True)
        doc = etree.fromstring(xml_bytes, parser)

        # Generar ID único para la firma
        signature_id = self._generate_signature_id()
        document_ref_id = 'Reference-ID-{}'.format(signature_id)

        # Crear builder
        builder = XAdESBuilder(self._cert_manager, signature_id)

        # 1. Calcular digest del documento (sin firma, transform enveloped)
        doc_digest_b64 = self._calculate_document_digest(doc)

        # 2. Construir SignedProperties
        signed_props = builder.build_signed_properties(document_ref_id)

        # 3. Calcular digest de SignedProperties
        signed_props_c14n = canonicalize(signed_props)
        signed_props_digest = hashlib.sha1(signed_props_c14n).digest()
        signed_props_digest_b64 = base64.b64encode(signed_props_digest)

        # 4. Construir SignedInfo
        signed_info = builder.build_signed_info(
            doc_digest_b64,
            signed_props_digest_b64,
            document_ref_id
        )

        # 5. Canonicalizar SignedInfo y firmar
        signed_info_c14n = canonicalize(signed_info)
        signature_b64 = self._cert_manager.sign_data_b64(signed_info_c14n)

        # 6. Construir la firma completa
        signature_element = self._build_complete_signature(
            builder,
            signed_info,
            signature_b64,
            signed_props,
            signature_id
        )

        # 7. Insertar firma en el documento
        doc.append(signature_element)

        # 8. Serializar el documento firmado
        result = etree.tostring(doc, encoding='UTF-8', xml_declaration=True)

        # IMPORTANTE: Asegurar que la salida tenga LF (no CRLF)
        if isinstance(result, bytes):
            result = result.replace(b'\r\n', b'\n').replace(b'\r', b'\n')

        return result

    def _generate_signature_id(self):
        """
        Genera un ID único para la firma (6 dígitos).

        Returns:
            str: ID numérico de 6 dígitos
        """
        return str(random.randint(100000, 999999))

    def _calculate_document_digest(self, doc):
        """
        Calcula el digest SHA1 del documento aplicando transform enveloped.

        Args:
            doc: Elemento raíz del documento

        Returns:
            str: Digest SHA1 en base64
        """
        # Crear copia profunda para no modificar el original
        doc_copy = etree.fromstring(etree.tostring(doc))

        # Eliminar cualquier firma existente (transform enveloped)
        for signature in doc_copy.findall('.//{{{}}}{}'.format(NS_DS, 'Signature')):
            signature.getparent().remove(signature)

        # Canonicalizar y calcular hash
        doc_c14n = canonicalize(doc_copy)
        doc_digest = hashlib.sha1(doc_c14n).digest()

        result = base64.b64encode(doc_digest)
        if not PY2:
            result = result.decode('ascii')
        return result

    def _build_complete_signature(self, builder, signed_info, signature_b64,
                                   signed_props, signature_id):
        """
        Construye el elemento Signature completo.

        Args:
            builder: Instancia de XAdESBuilder
            signed_info: Elemento SignedInfo
            signature_b64: Firma RSA-SHA1 en base64
            signed_props: Elemento SignedProperties
            signature_id: ID de la firma

        Returns:
            lxml.etree.Element: Elemento Signature completo
        """
        # Crear elemento Signature raíz
        signature = etree.Element(
            '{{{}}}{}'.format(NS_DS, 'Signature'),
            attrib={'Id': 'Signature{}'.format(signature_id)},
            nsmap={'ds': NS_DS}
        )

        # Agregar SignedInfo
        signed_info_copy = etree.SubElement(
            signature,
            '{{{}}}{}'.format(NS_DS, 'SignedInfo'),
            attrib={'Id': 'Signature-SignedInfo{}'.format(signature_id)}
        )

        # Copiar hijos de signed_info
        for child in signed_info:
            signed_info_copy.append(child)

        # Agregar SignatureValue
        sig_value = etree.SubElement(
            signature,
            '{{{}}}{}'.format(NS_DS, 'SignatureValue'),
            attrib={'Id': 'SignatureValue{}'.format(signature_id)}
        )
        sig_value.text = signature_b64

        # Agregar KeyInfo
        key_info = builder.build_key_info()
        key_info_new = etree.SubElement(
            signature,
            '{{{}}}{}'.format(NS_DS, 'KeyInfo'),
            attrib={'Id': 'Certificate{}'.format(signature_id)}
        )
        for child in key_info:
            key_info_new.append(child)

        # Agregar Object con QualifyingProperties
        obj = etree.SubElement(
            signature,
            '{{{}}}{}'.format(NS_DS, 'Object'),
            attrib={'Id': 'Object{}'.format(signature_id)}
        )

        qual_props = etree.SubElement(
            obj,
            '{{{}}}{}'.format(NS_ETSI, 'QualifyingProperties'),
            attrib={'Target': '#Signature{}'.format(signature_id)},
            nsmap={'etsi': NS_ETSI}
        )
        qual_props.append(signed_props)

        return signature