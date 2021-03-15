#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: prereceivecli.py
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
Main code for prereceivecli.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import argparse
import json
import logging
import logging.config
import os
from dataclasses import dataclass

import boto3
import botocore

from .configuration import HASHES_SCHEMA
from .lib import (get_project,
                  get_table_for_project_group,
                  send_slack_message,
                  HashChecker,
                  SecurityEntry,
                  parse_hook_input)


@dataclass
class AwsCredentials:
    """Stores AWS Credentials."""

    access_key_id: str
    secret_access_key: str
    session_token: str


__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''26-02-2019'''
__copyright__ = '''Copyright 2019, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos", "Alberto Rodriguez Garcia"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''prereceivecli'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

LOGGERS_TO_DISABLE = ['botocore.credentials']


def get_arguments():
    """Gets us the cli arguments.

    Returns the args as parsed from the argsparser.
    """
    # https://docs.python.org/3/library/argparse.html
    parser = argparse.ArgumentParser(description=('A cli that implements a git server side pre-receive hook that gets '
                                                  'driven from dynamodb and reports to slack offending pushes.'))
    excluding_key_arn = parser.add_mutually_exclusive_group(required=True)
    excluding_secret_token = parser.add_mutually_exclusive_group()
    excluding_key_token = parser.add_mutually_exclusive_group()
    excluding_secret_arn = parser.add_mutually_exclusive_group()
    key = excluding_key_arn.add_argument('--key', '-k',
                                         dest='access_key',
                                         action='store',
                                         help='The aws access key',
                                         type=str,
                                         required=False)
    arn = excluding_key_arn.add_argument('--arn', '-arn',
                                         dest='aws_role_arn',
                                         action='store',
                                         help='The aws role arn, defaults to environment variable',
                                         type=str,
                                         required=False)
    token = excluding_secret_token.add_argument('--token', '-token',
                                                dest='aws_web_identity_token_file',
                                                action='store',
                                                help='The aws web identity token file, defaults to environment variable',
                                                type=argparse.FileType('r'),
                                                required=False)
    secret = excluding_secret_token.add_argument('--secret', '-s',
                                                 dest='secret_key',
                                                 action='store',
                                                 help='The aws secret key',
                                                 type=str,
                                                 required=False)
    # See: https://bugs.python.org/issue10984#msg219660
    excluding_key_token._group_actions.extend([key, token])  # pylint: disable=protected-access
    excluding_secret_arn._group_actions.extend([arn, secret])  # pylint: disable=protected-access
    parser.add_argument('--log-config',
                        '-l',
                        action='store',
                        dest='logger_config',
                        help='The location of the logging config json file',
                        default='')
    parser.add_argument('--log-level',
                        '-L',
                        help='Provide the log level. Defaults to info.',
                        dest='log_level',
                        action='store',
                        default='info',
                        choices=['debug',
                                 'info',
                                 'warning',
                                 'error',
                                 'critical'])
    parser.add_argument('--slack-web-hook', '-w',
                        dest='web_hook',
                        action='store',
                        help='The slack web_hook to post messages to',
                        type=str,
                        required=True)
    parser.add_argument('--region', '-r',
                        dest='region',
                        action='store',
                        help='The aws region to use',
                        type=str,
                        required=True)
    feature_parser = parser.add_mutually_exclusive_group(required=False)
    feature_parser.add_argument('--aggressive-check', '-a',
                                dest='aggressive',
                                action='store_true',
                                help=('Flag noting whether the project should be rejected if no entry in the security '
                                      'table'))
    feature_parser.add_argument('--no-aggressive-check', '-n',
                                dest='aggressive',
                                action='store_false',
                                help=('Flag noting whether the project should be rejected if no entry in the security '
                                      'table'))
    parser.set_defaults(aggressive=False)
    args = parser.parse_args()
    if all([args.access_key, args.secret_key is None]):
        parser.error("--key requires --secret.")
    elif all([args.aws_role_arn, args.aws_web_identity_token_file is None]):
        parser.error("--arn requires --token.")
    return args


def setup_logging(level, config_file=None):
    """Sets up the logging.

    Args:
        level: The level to log for.
        config_file: The config file with the logging configuration. If provided it superseeds the level arg.

    Returns:
        args: The parsed arguments.

    """
    # This will configure the logging, if the user has set a config file.
    # If there's no config file, logging will default to stdout.
    if config_file:
        # Get the config for the logger. Of course this needs exception
        # catching in case the file is not there and everything. Proper IO
        # handling is not shown here.
        configuration = json.loads(open(config_file).read())
        # Configure the logger
        logging.config.dictConfig(configuration)
    else:
        handler = logging.StreamHandler()
        handler.setLevel(level.upper())
        formatter = logging.Formatter(('%(asctime)s - '
                                       '%(name)s - '
                                       '%(levelname)s - '
                                       '%(message)s'))
        handler.setFormatter(formatter)
        LOGGER.addHandler(handler)
        LOGGER.setLevel(level.upper())
    for logger in LOGGERS_TO_DISABLE:
        logging.getLogger(logger).disabled = True


def get_credentials(args):
    """Gets AWS credentials.

    Needs the args to either assume role or get credentials

    Credentials:
        Credentials: The AWS credentials to set for our environment

    """
    if not all([args.access_key, args.secret_key]):
        client = boto3.client('sts',
                              aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                              aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                              aws_session_token=os.environ.get('AWS_SESSION_TOKEN'))
        with open(args.aws_web_identity_token_file.name, 'r') as opened_file:
            token = opened_file.read()
        try:
            response = client.assume_role_with_web_identity(RoleArn=args.aws_role_arn,
                                                            RoleSessionName='prereceive',
                                                            WebIdentityToken=token)
        except botocore.exceptions.ClientError:
            LOGGER.exception('client')
        return AwsCredentials(response['Credentials']['AccessKeyId'],
                              response['Credentials']['SecretAccessKey'],
                              response['Credentials']['SessionToken'])
    return AwsCredentials(args.access_key,
                          args.secret_key,
                          None)


def validate_commit(project, dynamodb_table, web_hook, aggressive_checking):
    """Validates that no unauthorized change has been performed on protected files on a specified commit.

    Args:
        project (Project): An object exposing attributes of the required variables.
        dynamodb_table (Table): The dynamodb table with the entries for the projects.
        web_hook (str): The url of the slack webhook.
        aggressive_checking (bool): If set any unmatched repositories will be rejected.

    Returns:
        success (bool): True if the commit is valid False otherwise.

    """
    entries = dynamodb_table.get_item(Key={'slug': project.slug}).get('Item', {})
    if aggressive_checking and not entries:
        message = f'No dynamodb entries found for project "{project.slug}", project rejected due to aggressive checking'
        LOGGER.info(message)
        # This print is required to provide feedback to the user through the git hook via stdout
        print(message)
        return False
    if not entries:
        LOGGER.info('No dynamodb entries found for project "%s", project not secured', project.slug)
        return True
    entries = HASHES_SCHEMA.validate(entries)
    entries = [SecurityEntry(entry.get('hashes', []),
                             entry.get('name', ''),
                             entry.get('type', '')) for entry in entries.get('protected_items', [])]
    if not any([entry.hashes for entry in entries]):
        LOGGER.info('No hashes found for project "%s" for any type, project not secured', project.slug)
        return True
    errors = HashChecker().verify(project, entries)
    success = False if errors else True  # pylint: disable=simplifiable-if-expression
    for error_message in errors:
        send_slack_message(web_hook, error_message)
    return success


def main():
    """Main method.

    This method holds what you want to execute when
    the script is run on command line.

    """
    try:
        args = get_arguments()
        setup_logging(args.log_level, args.logger_config)
        # get the base, commit and ref as provided by the calling pre-receive hook
        base, commit = parse_hook_input()
        project = get_project(base, commit)
        if not project.group:
            LOGGER.info('Action seems as automatic merge for project "%s" from user "%s" and not a pre-receive hook, '
                        'letting through', project.slug, project.username)
            raise SystemExit(0)
        if not project.commit:
            LOGGER.info('It seems only tags were pushed for project "%s" by username "%s", letting through',
                        project.slug, project.username)
            raise SystemExit(0)
        os.environ['AWS_DEFAULT_REGION'] = args.region
        dynamodb_table = get_table_for_project_group(project.group, get_credentials(args))
        if not dynamodb_table:
            LOGGER.info('Project "%s" does not appear to have security settings set, letting through...', project.slug)
            raise SystemExit(0)
        success = validate_commit(project, dynamodb_table, args.web_hook, args.aggressive)
    except Exception:
        LOGGER.exception('Some unexpected error occurred letting things through!')
        raise SystemExit(0)
    raise SystemExit(0 if success else 1)


if __name__ == '__main__':
    main()
