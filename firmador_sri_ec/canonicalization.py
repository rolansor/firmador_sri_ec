# -*- coding: utf-8 -*-
"""
Canonicalización XML (C14N) para firma XAdES-BES.

Implementa el algoritmo C14N según:
http://www.w3.org/TR/2001/REC-xml-c14n-20010315
"""

from __future__ import absolute_import, unicode_literals

from lxml import etree


def canonicalize(element, exclusive=False, with_comments=False):
    """
    Canonicaliza un elemento XML según el estándar C14N.

    Args:
        element: Elemento lxml a canonicalizar
        exclusive: Si True, usa C14N exclusivo (default: False)
        with_comments: Si True, incluye comentarios (default: False)

    Returns:
        bytes: XML canonicalizado como bytes
    """
    # Crear copia para no modificar el original
    element_copy = etree.fromstring(etree.tostring(element))

    # Canonicalizar
    result = etree.tostring(
        element_copy,
        method='c14n',
        exclusive=exclusive,
        with_comments=with_comments
    )

    # IMPORTANTE: Normalizar line endings a LF
    # Windows usa CRLF que produce digests diferentes
    result = result.replace(b'\r\n', b'\n').replace(b'\r', b'\n')

    return result