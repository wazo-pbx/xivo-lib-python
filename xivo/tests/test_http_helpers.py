# -*- coding: utf-8 -*-
# Copyright 2016-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
import json

from hamcrest import assert_that, equal_to
from mock import patch, sentinel, ANY

from xivo.http_helpers import (
    BodyFormatter,
    log_request,
    log_request_hide_token,
    LazyHeaderFormatter,
)


def _assert_json_equals(result, expected):
    serialized_result = json.loads(result)
    assert_that(serialized_result, equal_to(expected))


class TestLogRequest(unittest.TestCase):
    @patch('xivo.http_helpers.current_app')
    @patch('xivo.http_helpers.request')
    def test_log_request(self, request, current_app):
        request.url = '/foo/bar?token=1734768e-caf6'

        log_request(sentinel)

        current_app.logger.info.assert_called_once_with(
            ANY, request.remote_addr, request.method, request.url, sentinel.status_code
        )

    @patch('xivo.http_helpers.current_app')
    @patch('xivo.http_helpers.request')
    def test_log_request_hide_token(self, request, current_app):
        request.url = '/foo/bar?token=1734768e-caf6'

        log_request_hide_token(sentinel)

        expected_url = '/foo/bar?token=<hidden>'
        current_app.logger.info.assert_called_once_with(
            ANY, request.remote_addr, request.method, expected_url, sentinel.status_code
        )


class TestBodyFormatter(unittest.TestCase):
    def test_valid_json_body_no_hidden_field(self):
        body = b'{"one": 1, "two": 2, "three": 3}'

        formatter = BodyFormatter(body, hidden_fields=None)
        result = '{}'.format(formatter)

        _assert_json_equals(result, {'one': 1, 'two': 2, 'three': 3})

    def test_valid_json_body_with_hidden_field(self):
        body = b'{"one": 1, "two": 2, "three": 3}'

        formatter = BodyFormatter(body, hidden_fields=['two'])
        result = '{}'.format(formatter)

        _assert_json_equals(result, {'one': 1, 'two': '<hidden>', 'three': 3})

    def test_invalid_json_body_with_hidden_field(self):
        body = b'{"one": 1, "two": 2, "three": 3,}'  # See that trialing coma

        formatter = BodyFormatter(body, hidden_fields=['two'])
        result = '{}'.format(formatter)

        assert_that(result, equal_to('<hidden>'))

    def test_invalid_json_body_with_hidden_field_no_match(self):
        body = b'{"one": 1, "two": 2, "three": 3,}'  # See that trialing coma

        formatter = BodyFormatter(body, hidden_fields=['four'])
        result = '{}'.format(formatter)

        assert_that(result, equal_to('{"one": 1, "two": 2, "three": 3,}'))


class TestHeaderFormatter(unittest.TestCase):
    def test_that_tokens_are_partially_masked(self):
        raw = {'X-Auth-Token': '87916129-1897-408c-a12f-bc629ca6c480'}
        formatter = LazyHeaderFormatter(raw)

        result = '{}'.format(formatter)

        assert_that(
            result, equal_to("{'X-Auth-Token': 'XXXXXXXX-XXXX-XXXX-XXXX-XXXX9ca6c480'}")
        )

    def test_that_basic_authorization_is_masked(self):
        raw = {'Authorization': 'Basic cm9vdDpzdXBlcn1233M='}
        formatter = LazyHeaderFormatter(raw)

        result = '{}'.format(formatter)

        assert_that(result, equal_to("{'Authorization': 'Basic <hidden>'}"))

    def test_that_all_other_authorization_are_completely_masked(self):
        raw = {'Authorization': 'unknown'}
        formatter = LazyHeaderFormatter(raw)

        result = '{}'.format(formatter)

        assert_that(result, equal_to("{'Authorization': '<hidden>'}"))
