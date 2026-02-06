# -*- coding: utf-8 -*-
"""
Tests para el firmador XAdES-BES.

Para ejecutar los tests necesitas un certificado .p12 de prueba.
Configura las variables de entorno:
    CERT_PATH=/ruta/al/certificado.p12
    CERT_PASSWORD=clave_del_certificado
"""

from __future__ import absolute_import, unicode_literals

import os
import unittest

from lxml import etree


# XML de prueba (factura mínima válida)
XML_PRUEBA = '''<?xml version="1.0" encoding="UTF-8"?>
<factura id="comprobante" version="1.0.0">
    <infoTributaria>
        <ambiente>1</ambiente>
        <tipoEmision>1</tipoEmision>
        <razonSocial>EMPRESA DE PRUEBA S.A.</razonSocial>
        <nombreComercial>EMPRESA PRUEBA</nombreComercial>
        <ruc>0990000000001</ruc>
        <claveAcceso>1501202501099000000000110010010000000011234567819</claveAcceso>
        <codDoc>01</codDoc>
        <estab>001</estab>
        <ptoEmi>001</ptoEmi>
        <secuencial>000000001</secuencial>
        <dirMatriz>GUAYAQUIL - ECUADOR</dirMatriz>
    </infoTributaria>
    <infoFactura>
        <fechaEmision>15/01/2025</fechaEmision>
        <dirEstablecimiento>GUAYAQUIL - ECUADOR</dirEstablecimiento>
        <obligadoContabilidad>SI</obligadoContabilidad>
        <tipoIdentificacionComprador>04</tipoIdentificacionComprador>
        <razonSocialComprador>CLIENTE DE PRUEBA</razonSocialComprador>
        <identificacionComprador>0900000000</identificacionComprador>
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
            <descripcion>PRODUCTO DE PRUEBA</descripcion>
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


def get_cert_config():
    """Obtiene configuración del certificado de prueba."""
    cert_path = os.environ.get('CERT_PATH')
    cert_password = os.environ.get('CERT_PASSWORD')
    return cert_path, cert_password


def validate_signature_structure(xml_firmado):
    """
    Valida que el XML firmado tenga la estructura correcta de XAdES-BES.

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

    # Verificar elemento Signature
    signature = doc.find('.//{{{}}}{}'.format(ns_ds, 'Signature'))
    if signature is None:
        errores.append('Falta elemento ds:Signature')
        return False, errores

    # Verificar SignedInfo
    signed_info = signature.find('{{{}}}{}'.format(ns_ds, 'SignedInfo'))
    if signed_info is None:
        errores.append('Falta elemento ds:SignedInfo')
    else:
        # Verificar CanonicalizationMethod
        c14n = signed_info.find('{{{}}}{}'.format(ns_ds, 'CanonicalizationMethod'))
        if c14n is None:
            errores.append('Falta CanonicalizationMethod')

        # Verificar SignatureMethod
        sig_method = signed_info.find('{{{}}}{}'.format(ns_ds, 'SignatureMethod'))
        if sig_method is None:
            errores.append('Falta SignatureMethod')

        # Verificar References
        references = signed_info.findall('{{{}}}{}'.format(ns_ds, 'Reference'))
        if len(references) < 2:
            errores.append('Faltan References (esperado >= 2)')

    # Verificar SignatureValue
    sig_value = signature.find('{{{}}}{}'.format(ns_ds, 'SignatureValue'))
    if sig_value is None or not sig_value.text:
        errores.append('Falta o vacio SignatureValue')

    # Verificar KeyInfo
    key_info = signature.find('{{{}}}{}'.format(ns_ds, 'KeyInfo'))
    if key_info is None:
        errores.append('Falta elemento ds:KeyInfo')
    else:
        if key_info.find('.//{{{}}}{}'.format(ns_ds, 'X509Certificate')) is None:
            errores.append('Falta X509Certificate')

    # Verificar QualifyingProperties
    qual_props = signature.find('.//{{{}}}{}'.format(ns_etsi, 'QualifyingProperties'))
    if qual_props is None:
        errores.append('Falta QualifyingProperties')
    else:
        if qual_props.find('.//{{{}}}{}'.format(ns_etsi, 'SigningTime')) is None:
            errores.append('Falta SigningTime')
        if qual_props.find('.//{{{}}}{}'.format(ns_etsi, 'SigningCertificate')) is None:
            errores.append('Falta SigningCertificate')

    return len(errores) == 0, errores


class TestFirmador(unittest.TestCase):
    """Tests para la clase Firmador."""

    @classmethod
    def setUpClass(cls):
        """Configurar certificado para tests."""
        cls.cert_path, cls.cert_password = get_cert_config()
        cls.skip_tests = cls.cert_path is None or cls.cert_password is None

    def test_firma_basica(self):
        """Test de firma básica."""
        if self.skip_tests:
            self.skipTest('No hay certificado configurado (CERT_PATH, CERT_PASSWORD)')

        from firmador_sri_ec import Firmador

        firmador = Firmador(self.cert_path, self.cert_password)
        xml_firmado = firmador.firmar(XML_PRUEBA)

        self.assertIsNotNone(xml_firmado)
        self.assertIn(b'Signature', xml_firmado)

    def test_estructura_firma(self):
        """Test que la estructura de firma sea correcta."""
        if self.skip_tests:
            self.skipTest('No hay certificado configurado (CERT_PATH, CERT_PASSWORD)')

        from firmador_sri_ec import Firmador

        firmador = Firmador(self.cert_path, self.cert_password)
        xml_firmado = firmador.firmar(XML_PRUEBA)

        es_valido, errores = validate_signature_structure(xml_firmado)
        self.assertTrue(es_valido, 'Errores en estructura: {}'.format(errores))

    def test_firmar_texto(self):
        """Test que firmar_texto retorne string."""
        if self.skip_tests:
            self.skipTest('No hay certificado configurado (CERT_PATH, CERT_PASSWORD)')

        from firmador_sri_ec import Firmador

        firmador = Firmador(self.cert_path, self.cert_password)
        xml_firmado = firmador.firmar_texto(XML_PRUEBA)

        self.assertIsInstance(xml_firmado, str)
        self.assertIn('Signature', xml_firmado)

    def test_cache_certificado(self):
        """Test que el cache de certificados funcione."""
        if self.skip_tests:
            self.skipTest('No hay certificado configurado (CERT_PATH, CERT_PASSWORD)')

        from firmador_sri_ec import Firmador

        # Limpiar cache
        Firmador.limpiar_cache()

        # Crear dos firmadores con mismo certificado
        firmador1 = Firmador(self.cert_path, self.cert_password)
        firmador2 = Firmador(self.cert_path, self.cert_password)

        # Deberían usar el mismo signer interno
        self.assertIs(firmador1._signer, firmador2._signer)


class TestXAdESSigner(unittest.TestCase):
    """Tests para la clase XAdESSigner de bajo nivel."""

    @classmethod
    def setUpClass(cls):
        """Configurar certificado para tests."""
        cls.cert_path, cls.cert_password = get_cert_config()
        cls.skip_tests = cls.cert_path is None or cls.cert_password is None

    def test_sign_basico(self):
        """Test de firma con XAdESSigner."""
        if self.skip_tests:
            self.skipTest('No hay certificado configurado (CERT_PATH, CERT_PASSWORD)')

        from firmador_sri_ec import XAdESSigner

        signer = XAdESSigner(self.cert_path, self.cert_password)
        xml_firmado = signer.sign(XML_PRUEBA)

        self.assertIsNotNone(xml_firmado)
        self.assertIn(b'Signature', xml_firmado)


if __name__ == '__main__':
    unittest.main()