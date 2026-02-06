# -*- coding: utf-8 -*-
"""
Firmador XAdES-BES para comprobantes electrónicos del SRI Ecuador.

Implementación nativa en Python (sin dependencias Java) que cumple con
las especificaciones técnicas del SRI:

- Estándar: XAdES-BES
- Versión esquema: 1.3.2
- Tipo firma: ENVELOPED
- Algoritmo: RSA-SHA1
- Hash: SHA-1
- C14N: http://www.w3.org/TR/2001/REC-xml-c14n-20010315

Uso básico:
    from firmador_sri_ec import Firmador

    firmador = Firmador('/ruta/certificado.p12', 'clave')
    xml_firmado = firmador.firmar(xml_documento)

Compatible con Python 2.7 y Python 3.6+
"""

from __future__ import absolute_import, unicode_literals

__version__ = '1.0.0'
__author__ = 'Rolando Sornoza'
__email__ = 'rolansor@gmail.com'

from .firmador import Firmador
from .signer import XAdESSigner

__all__ = ['Firmador', 'XAdESSigner', '__version__']