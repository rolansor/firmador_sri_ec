# -*- coding: utf-8 -*-
"""
Manejo de certificados PKCS12 (.p12) para firma XAdES-BES.

Proporciona funciones para:
- Cargar certificados P12
- Extraer información del certificado (issuer, serial, modulus, exponent)
- Firmar datos con RSA-SHA1
"""

from __future__ import absolute_import, unicode_literals

import base64
import hashlib

from OpenSSL import crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .compat import ensure_bytes, PY2


class CertificateManager(object):
    """
    Gestor de certificados PKCS12 para firma electrónica.
    """

    def __init__(self, p12_path, password):
        """
        Carga un certificado PKCS12.

        Args:
            p12_path: Ruta al archivo .p12
            password: Clave del certificado (string)
        """
        self._p12_path = p12_path
        self._password = password
        self._pkcs12 = None
        self._certificate = None
        self._private_key = None
        self._crypto_private_key = None

        self._load_certificate()

    def _load_certificate(self):
        """Carga el certificado PKCS12 desde el archivo."""
        try:
            with open(self._p12_path, 'rb') as f:
                p12_data = f.read()

            pwd_bytes = ensure_bytes(self._password)

            # Cargar PKCS12 con pyOpenSSL
            self._pkcs12 = crypto.load_pkcs12(p12_data, pwd_bytes)
            self._certificate = self._pkcs12.get_certificate()
            self._private_key = self._pkcs12.get_privatekey()

            # Obtener clave privada para cryptography (firma RSA)
            self._crypto_private_key = self._private_key.to_cryptography_key()

        except Exception as e:
            raise ValueError('Error al cargar certificado {}: {}'.format(self._p12_path, str(e)))

    def get_certificate_der(self):
        """
        Obtiene el certificado en formato DER (binario).

        Returns:
            bytes: Certificado en formato DER
        """
        return crypto.dump_certificate(crypto.FILETYPE_ASN1, self._certificate)

    def get_certificate_b64(self):
        """
        Obtiene el certificado codificado en base64.

        Returns:
            str: Certificado en base64
        """
        der = self.get_certificate_der()
        result = base64.b64encode(der)
        if not PY2:
            result = result.decode('ascii')
        return result

    def get_certificate_digest_sha1(self):
        """
        Calcula el digest SHA1 del certificado DER.

        Returns:
            str: Hash SHA1 del certificado en base64
        """
        der = self.get_certificate_der()
        sha1_hash = hashlib.sha1(der).digest()
        result = base64.b64encode(sha1_hash)
        if not PY2:
            result = result.decode('ascii')
        return result

    def get_issuer_name(self):
        """
        Obtiene el Distinguished Name del emisor del certificado
        en formato RFC4514 (compatible con RFC2253).

        El SRI requiere que el IssuerName use el formato RFC4514 exacto:
        - OIDs no estándar como 2.5.4.97 deben mantener el formato OID numérico
        - Los valores de OIDs desconocidos deben estar en hexadecimal (#hex)

        IMPORTANTE: El SRI valida que el formato sea exactamente RFC4514.
        Usar "UNDEF" o nombres alternativos causa ERROR 39: FIRMA INVALIDA.

        Ejemplo de formato correcto para UANATACA:
        2.5.4.97=#0c0f56415445532d413636373231343939,CN=UANATACA CA2 2016,...

        Returns:
            str: DN del emisor en formato RFC4514
        """
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_der = self.get_certificate_der()
        cert_crypto = x509.load_der_x509_certificate(cert_der, default_backend())

        # Construir el DN manualmente en formato RFC4514
        return self._build_rfc4514_name(cert_crypto.issuer)

    def _build_rfc4514_name(self, name):
        """
        Construye un Distinguished Name en formato RFC4514.

        RFC4514 especifica:
        - Atributos estándar usan nombres cortos (CN, O, OU, L, C, etc.)
        - Atributos no estándar usan OID numérico (ej: 2.5.4.97)
        - Valores de atributos no estándar van en hexadecimal (#hex)
        - Los RDNs se listan en orden inverso (del más específico al más general)

        Args:
            name: objeto x509.Name de cryptography

        Returns:
            str: DN en formato RFC4514
        """
        # Mapeo de OIDs estándar a nombres cortos según RFC4514
        oid_names = {
            '2.5.4.3': 'CN',    # commonName
            '2.5.4.6': 'C',     # countryName
            '2.5.4.7': 'L',     # localityName
            '2.5.4.8': 'ST',    # stateOrProvinceName
            '2.5.4.9': 'STREET',  # streetAddress
            '2.5.4.10': 'O',    # organizationName
            '2.5.4.11': 'OU',   # organizationalUnitName
            '2.5.4.5': 'serialNumber',  # serialNumber
            '0.9.2342.19200300.100.1.25': 'DC',  # domainComponent
            '0.9.2342.19200300.100.1.1': 'UID',  # userId
        }

        parts = []
        # Iterar en orden inverso (RFC4514 requiere orden inverso)
        for attr in reversed(list(name)):
            oid = attr.oid.dotted_string
            value = attr.value

            if oid in oid_names:
                # OID estándar: usar nombre corto y valor como texto
                # Escapar caracteres especiales según RFC4514
                escaped_value = self._escape_rfc4514_value(value)
                parts.append('{}={}'.format(oid_names[oid], escaped_value))
            else:
                # OID no estándar: usar OID numérico y valor en hexadecimal
                # El valor debe codificarse como ASN.1 UTF8String (#0c...)
                hex_value = self._encode_asn1_utf8string_hex(value)
                parts.append('{}=#{}'.format(oid, hex_value))

        return ','.join(parts)

    def _escape_rfc4514_value(self, value):
        """
        Escapa caracteres especiales en un valor RFC4514.

        Caracteres que requieren escape: , + " \ < > ;
        Espacios al inicio o final también requieren escape.

        Args:
            value: Valor del atributo (string)

        Returns:
            str: Valor escapado
        """
        # Caracteres que requieren escape con backslash
        special_chars = [',', '+', '"', '\\', '<', '>', ';']

        result = []
        for i, char in enumerate(value):
            if char in special_chars:
                result.append('\\')
                result.append(char)
            elif char == ' ' and (i == 0 or i == len(value) - 1):
                # Espacios al inicio o final
                result.append('\\')
                result.append(char)
            elif char == '#' and i == 0:
                # # al inicio
                result.append('\\')
                result.append(char)
            else:
                result.append(char)

        return ''.join(result)

    def _encode_asn1_utf8string_hex(self, value):
        """
        Codifica un valor como ASN.1 UTF8String en hexadecimal.

        El formato es: 0c + longitud + valor_utf8_en_hex
        Donde 0c es el tag para UTF8String

        Args:
            value: Valor a codificar (string)

        Returns:
            str: Valor codificado en hexadecimal (sin el # inicial)
        """
        from .compat import ensure_bytes

        # Codificar valor a UTF-8
        value_bytes = ensure_bytes(value)

        # Tag UTF8String = 0x0c
        tag = 0x0c
        length = len(value_bytes)

        # Construir el valor ASN.1
        if PY2:
            if length < 128:
                asn1_bytes = chr(tag) + chr(length) + value_bytes
            elif length < 256:
                asn1_bytes = chr(tag) + chr(0x81) + chr(length) + value_bytes
            else:
                asn1_bytes = chr(tag) + chr(0x82) + chr(length >> 8) + chr(length & 0xff) + value_bytes
            # Convertir a hexadecimal
            return ''.join('{:02x}'.format(ord(b)) for b in asn1_bytes)
        else:
            if length < 128:
                asn1_bytes = bytes([tag, length]) + value_bytes
            elif length < 256:
                asn1_bytes = bytes([tag, 0x81, length]) + value_bytes
            else:
                asn1_bytes = bytes([tag, 0x82, length >> 8, length & 0xff]) + value_bytes
            # Convertir a hexadecimal
            return asn1_bytes.hex()

    def get_serial_number(self):
        """
        Obtiene el número serial del certificado.

        Returns:
            int: Número serial
        """
        return self._certificate.get_serial_number()

    def get_public_key_info(self):
        """
        Obtiene la información de la clave pública RSA.

        Returns:
            tuple: (modulus_bytes, exponent_bytes)
        """
        pub_key = self._certificate.get_pubkey()
        crypto_pub_key = pub_key.to_cryptography_key()
        public_numbers = crypto_pub_key.public_numbers()

        # Convertir modulus a bytes (big-endian, unsigned)
        modulus = public_numbers.n
        exponent = public_numbers.e

        # Calcular bytes necesarios para el modulus
        modulus_bytes_len = (modulus.bit_length() + 7) // 8
        modulus_bytes = self._int_to_bytes(modulus, modulus_bytes_len)

        # Exponent normalmente es 65537 (3 bytes)
        exponent_bytes_len = (exponent.bit_length() + 7) // 8
        exponent_bytes = self._int_to_bytes(exponent, exponent_bytes_len)

        return modulus_bytes, exponent_bytes

    def _int_to_bytes(self, value, length):
        """
        Convierte un entero a bytes big-endian.

        Args:
            value: Entero a convertir
            length: Longitud en bytes

        Returns:
            bytes: Representación en bytes
        """
        if PY2:
            result = []
            for _ in range(length):
                result.append(chr(value & 0xFF))
                value >>= 8
            return ''.join(reversed(result))
        else:
            return value.to_bytes(length, byteorder='big')

    def get_rsa_modulus_b64(self):
        """
        Obtiene el módulo RSA en base64.

        Returns:
            str: Módulo RSA en base64
        """
        modulus_bytes, _ = self.get_public_key_info()
        result = base64.b64encode(modulus_bytes)
        if not PY2:
            result = result.decode('ascii')
        return result

    def get_rsa_exponent_b64(self):
        """
        Obtiene el exponente RSA en base64.

        Returns:
            str: Exponente RSA en base64
        """
        _, exponent_bytes = self.get_public_key_info()
        result = base64.b64encode(exponent_bytes)
        if not PY2:
            result = result.decode('ascii')
        return result

    def sign_data(self, data):
        """
        Firma datos con RSA-SHA1 usando PKCS#1 v1.5.

        Args:
            data: Datos a firmar (bytes o string)

        Returns:
            bytes: Firma RSA-SHA1
        """
        data = ensure_bytes(data)

        # Firmar con RSA PKCS#1 v1.5 y SHA1
        signature = self._crypto_private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA1()
        )

        return signature

    def sign_data_b64(self, data):
        """
        Firma datos y retorna la firma en base64.

        Args:
            data: Datos a firmar

        Returns:
            str: Firma en base64
        """
        signature = self.sign_data(data)
        result = base64.b64encode(signature)
        if not PY2:
            result = result.decode('ascii')
        return result