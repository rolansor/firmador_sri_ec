# -*- coding: utf-8 -*-
"""
Ejemplo básico de uso del firmador XAdES-BES.

Este ejemplo muestra cómo firmar una factura electrónica del SRI Ecuador.

Uso:
    python ejemplo_basico.py

Requiere:
    - Certificado .p12 en la carpeta 'firmas/'
    - Configurar CERT_PASSWORD con la clave del certificado
"""

from __future__ import absolute_import, unicode_literals, print_function

import os
import sys

# Si no está instalado el paquete, agregar el directorio padre al path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from firmador_sri_ec import Firmador


# Configuración
CERT_PATH = os.path.join(PROJECT_DIR, 'firmas', 'certificado.p12')
CERT_PASSWORD = os.environ.get('CERT_PASSWORD', 'tu_clave_aqui')


# XML de ejemplo (factura mínima)
XML_FACTURA = '''<?xml version="1.0" encoding="UTF-8"?>
<factura id="comprobante" version="1.0.0">
    <infoTributaria>
        <ambiente>1</ambiente>
        <tipoEmision>1</tipoEmision>
        <razonSocial>MI EMPRESA S.A.</razonSocial>
        <nombreComercial>MI EMPRESA</nombreComercial>
        <ruc>0990000000001</ruc>
        <claveAcceso>0602202601099000000000110010010000000011234567819</claveAcceso>
        <codDoc>01</codDoc>
        <estab>001</estab>
        <ptoEmi>001</ptoEmi>
        <secuencial>000000001</secuencial>
        <dirMatriz>GUAYAQUIL - ECUADOR</dirMatriz>
    </infoTributaria>
    <infoFactura>
        <fechaEmision>06/02/2026</fechaEmision>
        <dirEstablecimiento>GUAYAQUIL - ECUADOR</dirEstablecimiento>
        <obligadoContabilidad>SI</obligadoContabilidad>
        <tipoIdentificacionComprador>04</tipoIdentificacionComprador>
        <razonSocialComprador>CLIENTE EJEMPLO</razonSocialComprador>
        <identificacionComprador>0900000000001</identificacionComprador>
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
        <pagos>
            <pago>
                <formaPago>01</formaPago>
                <total>115.00</total>
            </pago>
        </pagos>
    </infoFactura>
    <detalles>
        <detalle>
            <codigoPrincipal>PROD001</codigoPrincipal>
            <descripcion>PRODUCTO DE EJEMPLO</descripcion>
            <cantidad>1</cantidad>
            <precioUnitario>100.00</precioUnitario>
            <descuento>0.00</descuento>
            <precioTotalSinImpuesto>100.00</precioTotalSinImpuesto>
            <impuestos>
                <impuesto>
                    <codigo>2</codigo>
                    <codigoPorcentaje>4</codigoPorcentaje>
                    <tarifa>15.00</tarifa>
                    <baseImponible>100.00</baseImponible>
                    <valor>15.00</valor>
                </impuesto>
            </impuestos>
        </detalle>
    </detalles>
</factura>'''


def main():
    """Ejemplo de firma de factura."""
    print('=' * 60)
    print('EJEMPLO: Firmador XAdES-BES para SRI Ecuador')
    print('=' * 60)

    # Verificar que existe el certificado
    if not os.path.exists(CERT_PATH):
        print('')
        print('ERROR: No se encontró el certificado en:')
        print('  {}'.format(CERT_PATH))
        print('')
        print('Por favor:')
        print('1. Copia tu certificado .p12 a la carpeta "firmas/"')
        print('2. Renómbralo a "certificado.p12" o modifica CERT_PATH')
        print('3. Configura la variable de entorno CERT_PASSWORD')
        print('')
        return

    print('')
    print('Certificado: {}'.format(CERT_PATH))
    print('')

    # Crear firmador
    print('Creando firmador...')
    firmador = Firmador(CERT_PATH, CERT_PASSWORD)
    print('OK: Firmador creado')
    print('')

    # Firmar documento
    print('Firmando documento...')
    xml_firmado = firmador.firmar(XML_FACTURA)
    print('OK: Documento firmado ({} bytes)'.format(len(xml_firmado)))
    print('')

    # Guardar resultado
    output_path = os.path.join(SCRIPT_DIR, 'factura_firmada.xml')
    with open(output_path, 'wb') as f:
        f.write(xml_firmado)
    print('Guardado en: {}'.format(output_path))

    print('')
    print('=' * 60)
    print('FIRMA COMPLETADA EXITOSAMENTE')
    print('=' * 60)


if __name__ == '__main__':
    main()