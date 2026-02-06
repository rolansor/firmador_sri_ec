# -*- coding: utf-8 -*-
"""
Módulo de compatibilidad Python 2/3.

Proporciona abstracciones para manejar diferencias entre versiones.
"""

from __future__ import absolute_import, unicode_literals

import sys

PY2 = sys.version_info[0] == 2

if PY2:
    string_types = (str, unicode)
    text_type = unicode
    binary_type = str
else:
    string_types = (str,)
    text_type = str
    binary_type = bytes


def ensure_bytes(data, encoding='utf-8'):
    """
    Convierte datos a bytes.

    Args:
        data: String o bytes
        encoding: Codificación a usar (default: utf-8)

    Returns:
        bytes: Datos como bytes
    """
    if isinstance(data, binary_type):
        return data
    if isinstance(data, text_type):
        return data.encode(encoding)
    raise TypeError('Se esperaba str o bytes, se recibió {}'.format(type(data).__name__))


def ensure_text(data, encoding='utf-8'):
    """
    Convierte datos a texto unicode.

    Args:
        data: String o bytes
        encoding: Codificación a usar (default: utf-8)

    Returns:
        str: Datos como texto
    """
    if isinstance(data, text_type):
        return data
    if isinstance(data, binary_type):
        return data.decode(encoding)
    raise TypeError('Se esperaba str o bytes, se recibió {}'.format(type(data).__name__))