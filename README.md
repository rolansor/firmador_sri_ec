# Firmador XAdES-BES para el SRI Ecuador

Librería Python nativa para firmar comprobantes electrónicos del SRI (Servicio de Rentas Internas) de Ecuador.

**No requiere Java** - Implementación 100% Python.

## Características

- Firma XAdES-BES según especificaciones del SRI Ecuador
- Compatible con Python 2.7 y Python 3.6+
- Sin dependencias de Java runtime
- Cache de certificados para máximo rendimiento (~1ms por firma)
- Compatible con Windows, Linux y macOS

## Especificaciones Técnicas

| Aspecto | Valor |
|---------|-------|
| Estándar | XAdES-BES |
| Versión esquema | 1.3.2 |
| Tipo firma | ENVELOPED |
| Algoritmo | RSA-SHA1 |
| Hash | SHA-1 |
| Canonicalización | http://www.w3.org/TR/2001/REC-xml-c14n-20010315 |

## Instalación

### Opción 1: Instalar con pip

```bash
pip install firmador-sri-ec
```

### Opción 2: Instalar desde código fuente

```bash
git clone https://github.com/rolansor/firmador_sri_ec.git
cd firmador_sri_ec
pip install .
```

### Opción 3: Uso sin instalación (importación manual)

Si prefieres no instalar el paquete, puedes copiar la carpeta `firmador_sri_ec/` a tu proyecto y usarla directamente:

```bash
# Copiar solo la carpeta del módulo
cp -r firmador_sri_ec/ /tu/proyecto/

# O clonar todo el repositorio
git clone https://github.com/rolansor/firmador_sri_ec.git
```

Luego en tu código:

```python
import sys
sys.path.insert(0, '/ruta/a/firmador_sri_ec')

from firmador_sri_ec import Firmador

firmador = Firmador('/ruta/certificado.p12', 'clave')
xml_firmado = firmador.firmar(xml_documento)
```

**Dependencias requeridas** (instalar manualmente si no usas pip):
```bash
pip install lxml pyOpenSSL cryptography
```

## Uso Básico

```python
from firmador_sri_ec import Firmador

# Crear firmador con certificado .p12
firmador = Firmador('/ruta/a/certificado.p12', 'clave_del_certificado')

# XML del comprobante (factura, nota de crédito, retención, etc.)
xml_documento = '''<?xml version="1.0" encoding="UTF-8"?>
<factura id="comprobante" version="1.0.0">
    <infoTributaria>
        <ambiente>1</ambiente>
        <tipoEmision>1</tipoEmision>
        <razonSocial>MI EMPRESA S.A.</razonSocial>
        <ruc>0990000000001</ruc>
        <claveAcceso>1501202501099000000000110010010000000011234567819</claveAcceso>
        <codDoc>01</codDoc>
        <estab>001</estab>
        <ptoEmi>001</ptoEmi>
        <secuencial>000000001</secuencial>
        <dirMatriz>GUAYAQUIL - ECUADOR</dirMatriz>
    </infoTributaria>
    <!-- resto del comprobante -->
</factura>'''

# Firmar
xml_firmado = firmador.firmar(xml_documento)

# Guardar
with open('factura_firmada.xml', 'wb') as f:
    f.write(xml_firmado)
```

## Uso Avanzado

### Obtener resultado como texto

```python
xml_firmado_texto = firmador.firmar_texto(xml_documento)
print(xml_firmado_texto)
```

### Usar el signer de bajo nivel

```python
from firmador_sri_ec import XAdESSigner

signer = XAdESSigner('/ruta/certificado.p12', 'clave')
xml_firmado = signer.sign(xml_documento)
```

### Limpiar cache de certificados

```python
from firmador_sri_ec import Firmador

# Útil si se actualiza el certificado durante la ejecución
Firmador.limpiar_cache()
```

## Tipos de Comprobantes Soportados

- Factura (01)
- Liquidación de compra (03)
- Nota de crédito (04)
- Nota de débito (05)
- Guía de remisión (06)
- Comprobante de retención (07)

## Requisitos

- Python 2.7 o Python 3.6+
- lxml >= 4.0.0
- pyOpenSSL >= 19.0.0
- cryptography >= 2.5

## Rendimiento

| Operación | Tiempo |
|-----------|--------|
| Primera firma (carga certificado) | ~100ms |
| Firmas posteriores (con cache) | ~1ms |

## Estructura del Proyecto

```
firmador_sri_ec/
├── firmador_sri_ec/     # Módulo principal
│   ├── __init__.py      # Exports principales
│   ├── firmador.py      # Clase Firmador (interfaz simple)
│   ├── signer.py        # XAdESSigner (lógica de firma)
│   ├── certificate.py   # Manejo de certificados P12
│   ├── xml_builder.py   # Construcción de elementos XAdES
│   ├── canonicalization.py  # Canonicalización XML (C14N)
│   ├── constants.py     # Constantes y namespaces
│   └── compat.py        # Compatibilidad Python 2/3
├── examples/            # Ejemplos de uso
│   ├── ejemplo_basico.py
│   └── ejemplo_avanzado.py
├── tests/               # Tests unitarios
├── firmas/              # Carpeta para certificados .p12 (no se commitean)
├── setup.py             # Instalación con pip
└── README.md
```

## Compatibilidad Windows

La librería maneja automáticamente las diferencias de line endings entre Windows (CRLF) y Unix (LF), asegurando que los digests sean correctos en cualquier plataforma.

## Licencia

MIT License - ver archivo [LICENSE](LICENSE)

## Contribuir

1. Fork el repositorio
2. Crea tu rama (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crea un Pull Request

## Autor

**Rolando Sornoza** - [rolansor@gmail.com](mailto:rolansor@gmail.com)

## Enlaces

- [Ficha Técnica SRI](https://www.sri.gob.ec/facturacion-electronica)
- [Especificaciones XAdES](https://www.w3.org/TR/XAdES/)