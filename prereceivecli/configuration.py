#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: configuration.py
#
# Copyright 2019 Costas Tyfoxylos
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
Main code for configuration.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import logging
import re
from schema import Schema

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''24-01-2019'''
__copyright__ = '''Copyright 2019, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''configuration'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

# SLUG_REGEX = re.compile(r'^[0-9]{3,}-[a-z0-9-]+')
SLUG_REGEX = re.compile(r'.*')

HASHES_SCHEMA = Schema({u'protected_items': [{u'hashes': [str],
                                              u'name': str,
                                              u'type': lambda x: x in ['file', 'directory']}],
                        u'slug': SLUG_REGEX.match})

ERROR_MESSAGE = (':fire:'
                 'Hello, *{project.username}* - you are not allowed to change {entry.type} *{entry.name}*.'
                 ' As a result this server is not accepting your push.\n'
                 'Calculated hash for {entry.type} *{entry.name}* was: *{calculated_hash}*'
                 '{diff}'
                 'If you want this commit to be accepted please contact the responsible team, '
                 'or add the hash to the appropriate entry in '
                 '<https://{region}.console.aws.amazon.com/dynamodb/home?region={region}#tables:'
                 'selected={project.group}_git_hook;tab=items|DynamoDB>')
