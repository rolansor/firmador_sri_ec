# -*- coding: utf-8 -*-
"""
Clase principal del firmador XAdES-BES para el SRI Ecuador.

Proporciona una interfaz simple y con cache de certificados para
máximo rendimiento en firmas repetidas.
"""

from __future__ import absolute_import, unicode_literals

from .signer import XAdESSigner
from .compat import ensure_bytes


# Cache global de signers para reutilizar certificados cargados
_signer_cache = {}


class Firmador(object):
    """
    Firmador XAdES-BES para comprobantes electrónicos del SRI Ecuador.

    Implementación nativa en Python (sin dependencias Java).

    Uso:
        firmador = Firmador('/ruta/certificado.p12', 'clave')
        xml_firmado = firmador.firmar(xml_documento)

    El certificado se carga una sola vez y se reutiliza en firmas
    posteriores para máximo rendimiento (~1ms por firma).
    """

    def __init__(self, p12_path, password):
        """
        Inicializa el firmador con el certificado PKCS12.

        Args:
            p12_path: Ruta al archivo .p12
            password: Clave del certificado
        """
        self._p12_path = p12_path
        self._password = password
        self._signer = None

        # Cargar signer (usa cache si ya existe)
        self._get_signer()

    def _get_signer(self):
        """
        Obtiene el signer, usando cache si está disponible.

        Returns:
            XAdESSigner: Instancia del firmador
        """
        cache_key = (self._p12_path, self._password)

        if cache_key not in _signer_cache:
            _signer_cache[cache_key] = XAdESSigner(self._p12_path, self._password)

        self._signer = _signer_cache[cache_key]
        return self._signer

    def firmar(self, xml_documento):
        """
        Firma un documento XML con XAdES-BES.

        El documento debe ser un XML válido del SRI con el elemento
        raíz teniendo id="comprobante".

        Args:
            xml_documento: XML del comprobante (string o bytes)

        Returns:
            bytes: XML firmado como bytes UTF-8
        """
        # Limpiar XML de caracteres problemáticos
        if isinstance(xml_documento, bytes):
            xml_clean = xml_documento.rstrip()
        else:
            xml_clean = xml_documento.rstrip()

        # Eliminar whitespace innecesario
        xml_clean = xml_clean.replace('\n', '').replace('\r', '').replace('\t', '')

        return self._signer.sign(xml_clean)

    def firmar_texto(self, xml_documento):
        """
        Firma un documento XML y retorna como texto.

        Args:
            xml_documento: XML del comprobante (string o bytes)

        Returns:
            str: XML firmado como string UTF-8
        """
        resultado = self.firmar(xml_documento)
        if isinstance(resultado, bytes):
            return resultado.decode('utf-8')
        return resultado

    @staticmethod
    def limpiar_cache():
        """
        Limpia el cache de certificados.

        Útil si se necesita recargar certificados después de
        actualizarlos o para liberar memoria.
        """
        global _signer_cache
        _signer_cache = {}