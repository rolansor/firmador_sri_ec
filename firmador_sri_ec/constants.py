# -*- coding: utf-8 -*-
"""
Constantes para firma XAdES-BES según especificaciones del SRI Ecuador.
"""

from __future__ import absolute_import, unicode_literals

# Namespaces XML
NS_DS = 'http://www.w3.org/2000/09/xmldsig#'
NS_ETSI = 'http://uri.etsi.org/01903/v1.3.2#'

# Algoritmos
ALG_C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
ALG_SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1'
ALG_RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
ALG_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'

# Identificadores XAdES
XADES_SIGNED_PROPS = 'http://uri.etsi.org/01903#SignedProperties'
