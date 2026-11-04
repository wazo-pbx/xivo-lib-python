# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from prometheus_flask_exporter import RESTfulPrometheusMetrics

if TYPE_CHECKING:
    from flask import Flask
    from flask_restful import Api
    from prometheus_client import CollectorRegistry


def init_flask_metrics(
    api: Api,
    metrics_decorator: Callable[[Callable[..., Any]], Callable[..., Any]] | None = None,
    registry: CollectorRegistry | None = None,
) -> RESTfulPrometheusMetrics:
    """Serve the app's metrics at <api prefix>/metrics, without authentication.

    Deny the route in nginx, or restrict it with `metrics_decorator`."""
    metrics = RESTfulPrometheusMetrics.for_app_factory(
        api,
        path=f'{api.prefix}/metrics',
        group_by='endpoint',
        metrics_decorator=metrics_decorator,
        registry=registry,
    )
    if api.app is not None:
        metrics.init_app(api.app, api)
        return metrics

    # An Api bound later with init_app() gets its metrics when it is bound
    bind_api = api.init_app

    def init_app(app: Flask) -> None:
        bind_api(app)
        metrics.init_app(app, api)

    api.init_app = init_app
    return metrics


class Plugin:
    """The `metrics` plugin of services that pass their Flask-RESTful `api`."""

    def load(self, dependencies: Mapping[str, Any]) -> None:
        init_flask_metrics(dependencies['api'])
