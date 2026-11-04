# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from functools import wraps
from unittest.mock import patch

from flask import Flask
from flask_restful import Api, Resource
from hamcrest import assert_that, contains_string, equal_to, not_
from prometheus_client import CollectorRegistry

from ..metrics import Plugin, init_flask_metrics


class ItemsResource(Resource):
    def get(self):
        return {'items': []}

    def post(self):
        return {'created': True}, 201


class TestInitFlaskMetrics(unittest.TestCase):
    def setUp(self):
        self.app = Flask('test')
        self.api = Api(self.app, prefix='/1.0')
        self.api.add_resource(ItemsResource, '/items', endpoint='items')
        self.client = self.app.test_client()

    def test_metrics_served_under_api_prefix_without_token(self):
        init_flask_metrics(self.api, registry=CollectorRegistry())

        response = self.client.get('/1.0/metrics')

        assert_that(response.status_code, equal_to(200))
        assert_that(self.client.get('/metrics').status_code, equal_to(404))

    def test_requests_are_counted_by_endpoint_and_status(self):
        init_flask_metrics(self.api, registry=CollectorRegistry())

        self.client.get('/1.0/items')
        self.client.post('/1.0/items')
        body = self.client.get('/1.0/metrics').get_data(as_text=True)

        assert_that(
            body,
            contains_string('flask_http_request_total{method="GET",status="200"} 1.0'),
        )
        assert_that(
            body,
            contains_string(
                'flask_http_request_duration_seconds_count'
                '{endpoint="items",method="GET",status="200"} 1.0'
            ),
        )
        assert_that(
            body,
            contains_string(
                'flask_http_request_duration_seconds_count'
                '{endpoint="items",method="POST",status="201"} 1.0'
            ),
        )

    def test_metrics_requests_are_not_counted(self):
        init_flask_metrics(self.api, registry=CollectorRegistry())

        self.client.get('/1.0/metrics')
        body = self.client.get('/1.0/metrics').get_data(as_text=True)

        assert_that(body, not_(contains_string('prometheus_metrics')))

    def test_metrics_decorator_restricts_the_route(self):
        def deny(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                return 'forbidden', 403

            return wrapper

        init_flask_metrics(
            self.api, metrics_decorator=deny, registry=CollectorRegistry()
        )

        assert_that(self.client.get('/1.0/metrics').status_code, equal_to(403))
        assert_that(self.client.get('/1.0/items').status_code, equal_to(200))

    def test_api_bound_after_init_serves_metrics(self):
        app = Flask('late')
        api = Api(prefix='/1.0')
        api.add_resource(ItemsResource, '/items', endpoint='items')
        client = app.test_client()

        init_flask_metrics(api, registry=CollectorRegistry())
        api.init_app(app)
        client.get('/1.0/items')
        body = client.get('/1.0/metrics').get_data(as_text=True)

        assert_that(
            body,
            contains_string(
                'flask_http_request_duration_seconds_count'
                '{endpoint="items",method="GET",status="200"} 1.0'
            ),
        )
        assert_that(client.get('/1.0/items').status_code, equal_to(200))


class TestPlugin(unittest.TestCase):
    @patch('prometheus_client.REGISTRY', CollectorRegistry())
    def test_load_serves_metrics_on_the_api(self):
        app = Flask('test')
        api = Api(app, prefix='/0.1')
        api.add_resource(ItemsResource, '/items', endpoint='items')
        client = app.test_client()

        Plugin().load({'api': api})
        client.get('/0.1/items')
        body = client.get('/0.1/metrics').get_data(as_text=True)

        assert_that(
            body,
            contains_string(
                'flask_http_request_duration_seconds_count'
                '{endpoint="items",method="GET",status="200"} 1.0'
            ),
        )
