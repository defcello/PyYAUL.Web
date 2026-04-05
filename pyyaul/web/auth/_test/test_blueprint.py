from unittest import TestCase
from unittest.mock import MagicMock, patch
from collections import deque
from types import SimpleNamespace
import time

import flask

from pyyaul.web.auth.blueprint import (
    _USER_RATE_LIMIT_RESPONSE_MESSAGE,
    _UserRateLimiter,
    BlueprintContext,
    DEFAULT_SECURITY_HEADERS,
    _REQUEST_LOGGER_NAME,
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

    def test_registers_request_logging_for_app_routes(self):
        app = flask.Flask(__name__)
        app.secret_key = 'testing'
        blueprintContext = BlueprintContext('auth', __name__, MagicMock())

        @app.route('/probe')
        def page_probe():
            return flask.make_response('created', 201)

        app.register_blueprint(blueprintContext.blueprint)

        with self.assertLogs(_REQUEST_LOGGER_NAME, level='INFO') as captured_logs:
            response = app.test_client().get('/probe')

        self.assertEqual(201, response.status_code)
        self.assertRegex(captured_logs.output[0], r'INFO:pyyaul\.web\.request:GET /probe 201 \d+ms')


class Test__UserRateLimiter(TestCase):

    def test_allow_blocks_when_limit_exceeded(self):
        limiter = _UserRateLimiter(2, 60)

        self.assertTrue(limiter.allow(1))
        self.assertTrue(limiter.allow(1))
        self.assertFalse(limiter.allow(1))

    def test_allow_separates_users(self):
        limiter = _UserRateLimiter(1, 60)

        self.assertTrue(limiter.allow(1))
        self.assertTrue(limiter.allow(2))
        self.assertFalse(limiter.allow(1))

    def test_prune_stale_removes_expired_and_empty_entries(self):
        limiter = _UserRateLimiter(1, 60)
        now_ts = time.time()
        limiter._records = {
            1: deque(),
            2: deque([now_ts - 120]),
            3: deque([now_ts - 30]),
        }

        limiter.prune_stale(now_ts - limiter.window_seconds)

        self.assertNotIn(1, limiter._records)
        self.assertNotIn(2, limiter._records)
        self.assertIn(3, limiter._records)

    def test_allow_allows_again_after_window_expires(self):
        limiter = _UserRateLimiter(1, 0.05)

        self.assertTrue(limiter.allow(1))
        self.assertFalse(limiter.allow(1))

        time.sleep(0.06)

        self.assertTrue(limiter.allow(1))


class Test_BlueprintContext_userRateLimit(TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.secret_key = 'testing'
        self.blueprintContext = BlueprintContext('auth', __name__, MagicMock())
        self.session_record = MagicMock(wolc_authaccounts__user__id=7)

    def test_post_under_limit_passes(self):
        @self.blueprintContext.userRateLimit(max_requests=2, window_seconds=60)
        def page_probe(**_kwargs):
            return 'ok'

        with self.app.test_request_context('/account/password', method='POST'):
            response = page_probe(auth_authsession_session_record=self.session_record)

        self.assertEqual('ok', response)

    def test_post_over_limit_returns_429(self):
        @self.blueprintContext.userRateLimit(max_requests=1, window_seconds=60)
        def page_probe(**_kwargs):
            return 'ok'

        with self.app.test_request_context('/account/password', method='POST'):
            first_response = page_probe(auth_authsession_session_record=self.session_record)
            second_response = page_probe(auth_authsession_session_record=self.session_record)

        self.assertEqual('ok', first_response)
        self.assertEqual(429, second_response.status_code)
        self.assertEqual(_USER_RATE_LIMIT_RESPONSE_MESSAGE, second_response.get_data(as_text=True))

    def test_get_is_never_rate_limited(self):
        @self.blueprintContext.userRateLimit(max_requests=0, window_seconds=60)
        def page_probe(**_kwargs):
            return 'ok'

        with self.app.test_request_context('/account/password', method='GET'):
            response = page_probe(auth_authsession_session_record=self.session_record)

        self.assertEqual('ok', response)

    def test_unauthenticated_post_passes_through(self):
        @self.blueprintContext.userRateLimit(max_requests=0, window_seconds=60)
        def page_probe(**_kwargs):
            return 'ok'

        with self.app.test_request_context('/account/password', method='POST'):
            response = page_probe()

        self.assertEqual('ok', response)


class Test_BlueprintContext_audit_log_errors(TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.secret_key = 'testing'
        self.on_log_error = MagicMock()
        self.db = MagicMock()
        self.blueprintContext = BlueprintContext(
            'auth',
            __name__,
            self.db,
            on_log_error=self.on_log_error,
        )

        @self.app.route('/')
        def page_index():
            return 'index'

        self.app.register_blueprint(self.blueprintContext.blueprint)
        self.client = self.app.test_client()

    def test_authSessionPrivilegeRequired_forwards_callback(self):
        self.blueprintContext._authsession_session_record_read = MagicMock(
            return_value=SimpleNamespace(
                wolc_authaccounts__user__id=7,
                wolc_authsession__session__id=11,
            )
        )
        self.db.authaccounts_user_allowPrivilege_read.return_value = True

        @self.blueprintContext.authSessionPrivilegeRequired(('sudo',))
        def page_probe(**_kwargs):
            return 'ok'

        with self.app.test_request_context('/secure', method='GET'):
            response = page_probe()

        self.assertEqual('ok', response)
        self.db.authaccounts_user_allowPrivilege_read.assert_called_once_with(
            7,
            ('sudo',),
            session_id=11,
            on_log_error=self.on_log_error,
        )

    def test_login_success_suppresses_log_write_failure_and_invokes_callback(self):
        self.db.authaccounts_user_readByEmailOrUsername.return_value = SimpleNamespace(
            id=5,
            is_loginenabled=True,
            is_disabled=False,
            unlocked=None,
        )
        self.db.authaccounts_user_passwordHash_readByID.return_value = 'unused'
        self.db.authaccounts_loginmethod_id_readByName.return_value = 3
        self.db.authsession_session_create.return_value = SimpleNamespace(
            wolc_authsession__session__id=17,
            wolc_authsession__session__cookie_id='cookie-123',
            wolc_authaccounts__user__id=5,
        )
        self.db.authaccounts_user_login_log.side_effect = RuntimeError('success log failed')

        with patch('pyyaul.web.auth.blueprint._ip_rate_check_and_record', return_value=True), \
             patch('bcrypt.checkpw', return_value=True):
            response = self.client.post('/auth/login', data={
                'username_or_email': 'alice',
                'password': 'secret',
            })

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.headers['Location'].endswith('/'))
        self.on_log_error.assert_called_once()
        self.assertIsInstance(self.on_log_error.call_args.args[0], RuntimeError)

    def test_login_failure_suppresses_log_write_failure_and_invokes_callback(self):
        self.db.authaccounts_user_readByEmailOrUsername.return_value = SimpleNamespace(
            id=5,
            is_loginenabled=True,
            is_disabled=False,
            unlocked=None,
        )
        self.db.authaccounts_user_passwordHash_readByID.return_value = 'unused'
        self.db.authaccounts_loginmethod_id_readByName.return_value = 3
        self.db.authaccounts_user_login_consecutive_failures_count.return_value = 0
        self.db.authaccounts_user_login_log.side_effect = RuntimeError('failure log failed')

        with patch('pyyaul.web.auth.blueprint._ip_rate_check_and_record', return_value=True), \
             patch('pyyaul.web.auth.blueprint.time.sleep', return_value=None), \
             patch('bcrypt.checkpw', return_value=False):
            response = self.client.post('/auth/login', data={
                'username_or_email': 'alice',
                'password': 'wrong',
            })

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.headers['Location'].endswith('/auth/login'))
        self.on_log_error.assert_called_once()
        self.assertIsInstance(self.on_log_error.call_args.args[0], RuntimeError)
