#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: utils.py
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
Main code for utils.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import logging
import json
import os
import shutil
import pathlib
import sys
import shlex

from subprocess import Popen, PIPE, check_output, CalledProcessError
from contextlib import contextmanager
from dataclasses import dataclass

import boto3
import requests
from botocore.exceptions import NoRegionError, NoCredentialsError, ClientError
from commonutilslib import tempdir, Pushd
from prereceivecli.configuration import ERROR_MESSAGE
from prereceivecli.prereceivecliexceptions import GitExecutionPathNotFound

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''24-01-2019'''
__copyright__ = '''Copyright 2019, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos", "Sayantan Khanra"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''utils'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


@dataclass
class Project:
    """Models a project exposing attributes for slug, group and git_path."""

    slug: str
    group: str
    git_path: str
    git_command: str
    username: str
    commit: str
    base: str


@dataclass
class SecurityEntry:
    """Models a security entry exposing attributes for slug, type and git_path."""

    hashes: list
    name: str
    type: str


def parse_hook_input():
    """Parses the git hook input disregarding the tags reference."""
    hook_input = sys.stdin.read()
    base = None
    commit = None
    try:
        for line in hook_input.splitlines():
            temp_base, temp_commit, refs = line.strip().split()
            if refs.strip().startswith('refs/tags/'):
                LOGGER.info('Disregarding tag push with base: %s and commit: %s for tag %s',
                            temp_base, temp_commit, refs)
                continue
            base = temp_base
            commit = temp_commit
    except (ValueError, TypeError, AttributeError):
        LOGGER.error('Received invalid input from hook, bailing... Value provided was : %s', hook_input)
        raise SystemExit(0)
    return base, commit


def execute_command_with_returned_output(command):
    """Execute the command with returned output."""
    stdout = ''
    stderr = ''
    command = shlex.split(command)
    try:
        LOGGER.debug('Executing command %s', command)
        command_execution = check_output(command)
        stdout = command_execution.decode('utf-8')
    except CalledProcessError as command_execution:
        stderr = command_execution.stderr.decode('utf-8')
    success = bool(command_execution)
    return success, stdout.strip(), stderr.strip()


def send_slack_message(webhook, message):
    """Send a message to a webhook in slack.

    Args:
        webhook (str): The webhook to submit the message to
        message (str): The message to submit to slack

    Returns:
        (bool): True on success False otherwise

    """
    slack_data = {'text': f'{message}'}
    success = True
    if not webhook:
        LOGGER.warning('No web slack web hook provided, not reporting to slack')
        return success
    try:
        response = requests.post(webhook,
                                 data=json.dumps(slack_data),
                                 headers={'Content-Type': 'application/json'})
        if not response.ok:
            LOGGER.error('Request to slack returned an error %s, the response is:\n%s',
                         response.status_code, response.text)
    except Exception:  # pylint: disable=broad-except
        success = False
        LOGGER.exception('Problem encountered sending slack message.')
    return success


def get_project(base, commit):
    """Constructs a project object from a gitlab project path.

    Returns:
        (project): An object exposing the required attributes of the environment and the project

    """
    username = os.environ.get('GL_USERNAME')
    git_execution_path = os.environ.get('GIT_EXEC_PATH')
    if git_execution_path:
        git_command = f'{git_execution_path}/git'
    else:
        success, stdout, _ = execute_command_with_returned_output('git --exec-path')
        git_command = f'{stdout}/git' if success else None
    if not git_command:
        raise GitExecutionPathNotFound()
    git_path = os.environ.get('PWD')
    components = os.environ.get('GL_PROJECT_PATH').split('/')
    project_slug = components[-1]
    project_group = '/'.join(components[:-1])
    return Project(project_slug, project_group, git_path, git_command, username, commit, base)


def get_table_for_project_group(project_group, credentials):
    """Retrieves a dynamodb table following a specific naming convention.

    Args:
        project_group (str): The type of the project to look up the table for.
            Convention states that the table should be named {type, eg:infrastructure}_git_hook.
        credentials (AwsCredentials): An object holding the credentials passed from the authentication process.

    Returns:
        (dynamodb Table): if found else None

    """
    invalid_settings = 'Invalid aws credentials settings. Please set region and credentials properly'
    try:
        dynamodb = boto3.resource('dynamodb',
                                  aws_access_key_id=credentials.access_key_id,
                                  aws_secret_access_key=credentials.secret_access_key,
                                  aws_session_token=credentials.session_token)
    except NoRegionError:
        LOGGER.exception('')
        raise ValueError(invalid_settings)
    project_group = project_group.replace('/', '_').replace('-', '_')
    table = dynamodb.Table(f'{project_group}_git_hook')
    try:
        table.item_count
    except ClientError:
        LOGGER.debug('No table found for project group %s', project_group)
        return None
    except NoCredentialsError:
        LOGGER.error(invalid_settings)
        raise ValueError(invalid_settings)
    return table


@contextmanager
def no_quarantine():
    """Context manager that clears the GIT_QUARANTINE_PATH environment variable and restores it."""
    git_quarantine_path = os.environ.get('GIT_QUARANTINE_PATH')
    try:
        if git_quarantine_path is not None:
            del os.environ['GIT_QUARANTINE_PATH']
        yield
    finally:
        if git_quarantine_path is not None:
            os.environ['GIT_QUARANTINE_PATH'] = git_quarantine_path


class GitCheckout:
    """Implements a git rebuilding context manager for a pre-receive hook."""

    def __init__(self, project, hasher, entries):
        logger_name = u'{base}.{suffix}'.format(base=LOGGER_BASENAME,
                                                suffix=self.__class__.__name__)
        self._logger = logging.getLogger(logger_name)
        self.project = project
        self.hasher = hasher
        self.entries = entries
        self.temporary_directory = None
        self.git_directory = None
        self.working_directory = None

    def _execute_command(self, command):
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        out, err = process.communicate()
        if process.returncode:
            self._logger.error('Error executing command "%s"\n\tstderr: "%s"\n\tstdout: "%s"',
                               command, err, out)
        return True if not process.returncode else False  # pylint: disable=simplifiable-if-expression

    def __enter__(self):  # pylint: disable=inconsistent-return-statements
        with tempdir() as temporary_directory:
            self.temporary_directory = temporary_directory
            self.git_directory = pathlib.Path(temporary_directory).joinpath(self.project.slug, 'git')
            self.working_directory = pathlib.Path(temporary_directory).joinpath(self.project.slug, 'files')
            git_with_tree = [self.project.git_command, f'--work-tree={self.working_directory}']
            self._logger.info('Creating a copy of "%s" to "%s"', self.project.git_path, self.git_directory)
            shutil.copytree(self.project.git_path, self.git_directory)
            self._logger.info('Cloning "%s" to "%s"', self.git_directory, self.working_directory)
            if self._execute_command([self.project.git_command, 'clone', self.git_directory, self.working_directory]):
                self._logger.info('Changing directory to "%s"', self.git_directory)
                with Pushd(self.git_directory):
                    self._logger.info('Checking out commit "%s"', self.project.commit)
                    self._execute_command(git_with_tree + ['checkout', '-f', self.project.commit])
                    # self._logger.info('Resetting hard')
                    # self._execute_command(git_with_tree + ['reset', '--hard'])
                    # self._logger.info('Cleaning repo')
                    # self._execute_command(git_with_tree + ['clean', '-fdx'])
                    errors = []
                    for entry in self.entries:
                        if not entry.hashes:
                            self._logger.info('"%s": No hashes are set, skipping check for %s %s',
                                              self.project.slug, entry.type, entry.name)
                            continue
                        path = str(pathlib.Path(self.working_directory).absolute().joinpath(entry.name))
                        self._logger.info('"%s": Calculating hash for "%s" "%s" in path: "%s"',
                                          self.project.slug, entry.type, entry.name, path)
                        calculated_hash = getattr(self.hasher, f'hash_{entry.type}')(path)
                        if calculated_hash not in entry.hashes:
                            command = git_with_tree + ['diff', self.project.base, self.project.commit]
                            process = Popen(command, stdout=PIPE, stderr=PIPE)
                            out, _ = process.communicate()
                            error_message = (ERROR_MESSAGE.format(entry=entry,
                                                                  project=self.project,
                                                                  calculated_hash=calculated_hash,
                                                                  diff=self._render_diff(out.decode("utf-8"),
                                                                                         entry.name),
                                                                  region=os.environ['AWS_DEFAULT_REGION']))
                            errors.append(error_message)
                            self._logger.error(error_message)
                    return errors

    def _render_diff(self, text, file_name):
        text = self._filter_diff_entry(text, file_name)
        if text:
            output = (f'\nOffending diff is :\n'
                      f'```{text}```\n')
        else:
            output = '\nNo diff available.\n'
        return output

    def _filter_diff_entry(self, diff, file_name):
        diff = diff.replace('\ndiff', '\n|||diff')
        try:
            text = r''.join([line for line in diff.split('|||')
                             if file_name in line.splitlines()[0]])
        except IndexError:
            self._logger.warning('No diff found')
            text = ''
        return text

    def __exit__(self, exception_type, exception_value, traceback):
        self._logger.info('Cleaning up temporary directory "%s"', self.temporary_directory)
        self.git_directory = None
        self.working_directory = None
        self.temporary_directory = None
