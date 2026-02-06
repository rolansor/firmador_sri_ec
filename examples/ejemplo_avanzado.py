# -*- coding: utf-8 -*-
"""
Ejemplo avanzado de uso del firmador XAdES-BES.

Este ejemplo muestra:
- Firma de múltiples documentos
- Medición de rendimiento
- Validación de estructura de firma
- Manejo de errores

Uso:
    python ejemplo_avanzado.py
"""

from __future__ import absolute_import, unicode_literals, print_function

import os
import sys
import time

# Si no está instalado el paquete, agregar el directorio padre al path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from lxml import etree
from firmador_sri_ec import Firmador, XAdESSigner


# Configuración
CERT_PATH = os.path.join(PROJECT_DIR, 'firmas', 'certificado.p12')
CERT_PASSWORD = os.environ.get('CERT_PASSWORD', 'tu_clave_aqui')


def crear_factura_xml(secuencial):
    """Crea un XML de factura con el secuencial dado."""
    return '''<?xml version="1.0" encoding="UTF-8"?>
<factura id="comprobante" version="1.0.0">
    <infoTributaria>
        <ambiente>1</ambiente>
        <tipoEmision>1</tipoEmision>
        <razonSocial>MI EMPRESA S.A.</razonSocial>
        <ruc>0990000000001</ruc>
        <claveAcceso>060220260109900000000011001001{:09d}1234567819</claveAcceso>
        <codDoc>01</codDoc>
        <estab>001</estab>
        <ptoEmi>001</ptoEmi>
        <secuencial>{:09d}</secuencial>
        <dirMatriz>GUAYAQUIL</dirMatriz>
    </infoTributaria>
    <infoFactura>
        <fechaEmision>06/02/2026</fechaEmision>
        <totalSinImpuestos>100.00</totalSinImpuestos>
        <totalDescuento>0.00</totalDescuento>
        <totalConImpuestos>
            <totalImpuesto>
                <codigo>2</codigo>
                <codigoPorcentaje>4</codigoPorcentaje>
                <baseImponible>100.00</baseImponible>
                <valor>15.00</valor>
            </totalImpuesto>
        </totalConImpuestos>
        <propina>0.00</propina>
        <importeTotal>115.00</importeTotal>
        <moneda>DOLAR</moneda>
    </infoFactura>
    <detalles>
        <detalle>
            <codigoPrincipal>PROD001</codigoPrincipal>
            <descripcion>PRODUCTO</descripcion>
            <cantidad>1</cantidad>
            <precioUnitario>100.00</precioUnitario>
            <descuento>0.00</descuento>
            <precioTotalSinImpuesto>100.00</precioTotalSinImpuesto>
        </detalle>
    </detalles>
</factura>'''.format(secuencial, secuencial)


def validar_firma(xml_firmado):
    """
    Valida la estructura de la firma XAdES-BES.

    Returns:
        tuple: (es_valido, lista_errores)
    """
    errores = []

    try:
        if isinstance(xml_firmado, bytes):
            doc = etree.fromstring(xml_firmado)
        else:
            doc = etree.fromstring(xml_firmado.encode('utf-8'))
    except Exception as e:
        return False, ['Error parseando XML: {}'.format(str(e))]

    ns_ds = 'http://www.w3.org/2000/09/xmldsig#'
    ns_etsi = 'http://uri.etsi.org/01903/v1.3.2#'

    # Verificar Signature
    signature = doc.find('.//{{{}}}{}'.format(ns_ds, 'Signature'))
    if signature is None:
        errores.append('Falta ds:Signature')
        return False, errores

    # Verificar SignedInfo
    if signature.find('{{{}}}{}'.format(ns_ds, 'SignedInfo')) is None:
        errores.append('Falta SignedInfo')

    # Verificar SignatureValue
    sig_value = signature.find('{{{}}}{}'.format(ns_ds, 'SignatureValue'))
    if sig_value is None or not sig_value.text:
        errores.append('Falta SignatureValue')

    # Verificar KeyInfo con X509Certificate
    key_info = signature.find('{{{}}}{}'.format(ns_ds, 'KeyInfo'))
    if key_info is None:
        errores.append('Falta KeyInfo')
    elif key_info.find('.//{{{}}}{}'.format(ns_ds, 'X509Certificate')) is None:
        errores.append('Falta X509Certificate')

    # Verificar QualifyingProperties
    qual_props = signature.find('.//{{{}}}{}'.format(ns_etsi, 'QualifyingProperties'))
    if qual_props is None:
        errores.append('Falta QualifyingProperties')

    return len(errores) == 0, errores


def ejemplo_firma_multiple():
    """Ejemplo de firma de múltiples documentos con medición de rendimiento."""
    print('')
    print('EJEMPLO: Firma de múltiples documentos')
    print('-' * 50)

    if not os.path.exists(CERT_PATH):
        print('ERROR: No se encontró certificado en {}'.format(CERT_PATH))
        return

    # Crear firmador (carga certificado una vez)
    print('Cargando certificado...')
    inicio_carga = time.time()
    firmador = Firmador(CERT_PATH, CERT_PASSWORD)
    tiempo_carga = (time.time() - inicio_carga) * 1000
    print('Certificado cargado en {:.2f} ms'.format(tiempo_carga))
    print('')

    # Firmar múltiples documentos
    num_documentos = 10
    tiempos = []

    print('Firmando {} documentos...'.format(num_documentos))
    for i in range(1, num_documentos + 1):
        xml = crear_factura_xml(i)

        inicio = time.time()
        xml_firmado = firmador.firmar(xml)
        tiempo = (time.time() - inicio) * 1000
        tiempos.append(tiempo)

        # Validar estructura
        es_valido, errores = validar_firma(xml_firmado)
        estado = 'OK' if es_valido else 'ERROR: {}'.format(errores)

        print('  Doc {:2d}: {:.2f} ms - {}'.format(i, tiempo, estado))

    print('')
    print('Estadísticas:')
    print('  Promedio: {:.2f} ms'.format(sum(tiempos) / len(tiempos)))
    print('  Mínimo:   {:.2f} ms'.format(min(tiempos)))
    print('  Máximo:   {:.2f} ms'.format(max(tiempos)))
    print('  Total:    {:.2f} ms'.format(sum(tiempos)))


def ejemplo_bajo_nivel():
    """Ejemplo usando la clase XAdESSigner directamente."""
    print('')
    print('EJEMPLO: Uso de XAdESSigner (bajo nivel)')
    print('-' * 50)

    if not os.path.exists(CERT_PATH):
        print('ERROR: No se encontró certificado en {}'.format(CERT_PATH))
        return

    # Usar XAdESSigner directamente
    signer = XAdESSigner(CERT_PATH, CERT_PASSWORD)

    xml = crear_factura_xml(999)
    xml_firmado = signer.sign(xml)

    print('Documento firmado: {} bytes'.format(len(xml_firmado)))

    # Mostrar fragmento de la firma
    if b'<ds:SignatureValue' in xml_firmado:
        inicio = xml_firmado.find(b'<ds:SignatureValue')
        fin = xml_firmado.find(b'</ds:SignatureValue>') + 20
        print('')
        print('Fragmento de SignatureValue:')
        print(xml_firmado[inicio:inicio+100].decode('utf-8') + '...')


def ejemplo_manejo_errores():
    """Ejemplo de manejo de errores."""
    print('')
    print('EJEMPLO: Manejo de errores')
    print('-' * 50)

    # Error: certificado no existe
    print('')
    print('1. Certificado inexistente:')
    try:
        firmador = Firmador('/ruta/que/no/existe.p12', 'clave')
    except Exception as e:
        print('   Error capturado: {}'.format(type(e).__name__))

    # Error: contraseña incorrecta
    if os.path.exists(CERT_PATH):
        print('')
        print('2. Contraseña incorrecta:')
        try:
            firmador = Firmador(CERT_PATH, 'clave_incorrecta')
        except Exception as e:
            print('   Error capturado: {}'.format(type(e).__name__))


def main():
    """Ejecuta todos los ejemplos."""
    print('=' * 60)
    print('EJEMPLOS AVANZADOS: Firmador XAdES-BES')
    print('=' * 60)

    ejemplo_firma_multiple()
    ejemplo_bajo_nivel()
    ejemplo_manejo_errores()

    print('')
    print('=' * 60)
    print('EJEMPLOS COMPLETADOS')
    print('=' * 60)


if __name__ == '__main__':
    main()