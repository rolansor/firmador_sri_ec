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
        en formato RFC2253.

        Returns:
            str: DN del emisor
        """
        issuer = self._certificate.get_issuer()
        components = issuer.get_components()

        # Construir DN en orden inverso (RFC2253)
        dn_parts = []
        for name, value in reversed(components):
            # name y value son bytes
            if isinstance(name, bytes):
                name = name.decode('utf-8')
            if isinstance(value, bytes):
                value = value.decode('utf-8')
            dn_parts.append('{}={}'.format(name, value))

        return ','.join(dn_parts)

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