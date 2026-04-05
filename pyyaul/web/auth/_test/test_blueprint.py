from unittest import TestCase
from unittest.mock import MagicMock

import flask

from pyyaul.web.auth.blueprint import (
    BlueprintContext,
    DEFAULT_SECURITY_HEADERS,
    flaskResponse_securityHeaders_set,
)


class Test_flaskResponse_securityHeaders_set(TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.secret_key = 'testing'
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    def test_applies_default_headers(self):
        response = flask.make_response('ok')

        flaskResponse_securityHeaders_set(response)

        self.assertEqual(dict(DEFAULT_SECURITY_HEADERS), {
            key: response.headers.get(key)
            for key in DEFAULT_SECURITY_HEADERS
        })

    def test_preserves_route_specific_header_values(self):
        response = flask.make_response('ok')
        response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline'"

        flaskResponse_securityHeaders_set(response)

        self.assertEqual(
            "default-src 'self' 'unsafe-inline'",
            response.headers['Content-Security-Policy'],
        )
        self.assertEqual('DENY', response.headers['X-Frame-Options'])

    def test_allows_overrides_and_disabling_headers(self):
        response = flask.make_response('ok')

        flaskResponse_securityHeaders_set(response, {
            'Content-Security-Policy': "default-src 'self' 'unsafe-inline'",
            'Permissions-Policy': None,
        })

        self.assertEqual(
            "default-src 'self' 'unsafe-inline'",
            response.headers['Content-Security-Policy'],
        )
        self.assertNotIn('Permissions-Policy', response.headers)


class Test_BlueprintContext_security_headers(TestCase):

    def test_registers_after_request_hook_with_overrides(self):
        app = flask.Flask(__name__)
        app.secret_key = 'testing'
        blueprintContext = BlueprintContext(
            'auth',
            __name__,
            MagicMock(),
            security_headers={
                'Content-Security-Policy': "default-src 'self' 'unsafe-inline'",
            },
        )

        @blueprintContext.blueprint.route('/probe')
        def page_probe():
            return 'ok'

        app.register_blueprint(blueprintContext.blueprint)

        response = app.test_client().get('/auth/probe')

        self.assertEqual(
            "default-src 'self' 'unsafe-inline'",
            response.headers['Content-Security-Policy'],
        )
        self.assertEqual('nosniff', response.headers['X-Content-Type-Options'])
