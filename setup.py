# -*- coding: utf-8 -*-
"""
Setup para firmador_sri_ec - Firmador XAdES-BES para el SRI Ecuador.
"""

from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='firmador-sri-ec',
    version='1.0.0',
    author='Rolando Sornoza',
    author_email='rolansor@gmail.com',
    description='Firmador XAdES-BES nativo en Python para comprobantes electronicos del SRI Ecuador',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/rolansor/firmador_sri_ec',
    packages=find_packages(exclude=['tests', 'examples']),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security :: Cryptography',
        'Topic :: Text Processing :: Markup :: XML',
    ],
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*',
    install_requires=[
        'lxml>=4.0.0',
        'pyOpenSSL>=19.0.0',
        'cryptography>=2.5',
    ],
    extras_require={
        'dev': [
            'pytest>=4.0.0',
            'pytest-cov>=2.0.0',
        ],
    },
    keywords='xades sri ecuador factura electronica firma digital xml signature',
    project_urls={
        'Bug Reports': 'https://github.com/rolansor/firmador_sri_ec/issues',
        'Source': 'https://github.com/rolansor/firmador_sri_ec',
    },
)