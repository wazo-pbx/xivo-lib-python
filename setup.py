#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(
    name='xivo',
    version='1.0',
    description='These are useful python libraries to be used with XIVO code',
    author='Avencall',
    author_email='xivo-dev@lists.proformatique.com',
    url='http://projects.xivo.io/',
    packages=[
        'xivo',
        'xivo.asterisk',
        'xivo.cli',
        'xivo.cli.command',
        'xivo.cli.completion',
        'xivo.cli.source',
        'xivo.net',
        'xivo.ssl',
        'xivo.sys',
        'xivo.BackSQL',
    ],
)
