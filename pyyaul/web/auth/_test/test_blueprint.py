from unittest import TestCase
from unittest.mock import MagicMock, patch
from collections import deque
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import time

import flask

from pyyaul.web.auth.blueprint import (
    _IP_RATE_MAX_ATTEMPTS,
    _LOGIN_ACCOUNT_LOCKED_RESPONSE_MESSAGE,
    _LOGIN_IP_RATE_LIMIT_RESPONSE_MESSAGE,
    _USER_RATE_LIMIT_RESPONSE_MESSAGE,
    _UserRateLimiter,
    BlueprintContext,
    DEFAULT_SECURITY_HEADERS,
    _REQUEST_LOGGER_NAME,
    flaskApp_proxyFix_apply,
    flaskResponse_securityHeaders_set,
)


def _csrf_token_seed(client, token='test-csrf-token'):
    with client.session_transaction() as session:
        session['csrf_token'] = token
    return token


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


class Test_BlueprintContext_csrf(TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.secret_key = 'testing'
        self.blueprintContext = BlueprintContext('auth', __name__, MagicMock())

        @self.app.route('/probe-form', methods=['POST'])
        def page_probe_form():
            return 'ok'

        @self.app.route('/probe-json', methods=['POST'])
        def page_probe_json():
            return flask.jsonify({'ok': True})

        @self.app.route('/probe-token', methods=['GET'])
        def page_probe_token():
            return flask.render_template_string('<input value="{{ csrf_token }}">')

        self.app.register_blueprint(self.blueprintContext.blueprint)
        self.client = self.app.test_client()

    def test_context_processor_exposes_csrf_token(self):
        response = self.client.get('/probe-token')

        self.assertEqual(200, response.status_code)
        self.assertRegex(response.get_data(as_text=True), r'value="[0-9a-f]{64}"')

    def test_form_post_with_valid_csrf_token_passes(self):
        self.client.get('/probe-token')
        with self.client.session_transaction() as session:
            csrf_token = session['csrf_token']

        response = self.client.post('/probe-form', data={'csrf_token': csrf_token})

        self.assertEqual(200, response.status_code)
        self.assertEqual('ok', response.get_data(as_text=True))

    def test_form_post_without_csrf_token_is_rejected(self):
        response = self.client.post('/probe-form', data={})

        self.assertEqual(403, response.status_code)

    def test_json_post_bypasses_csrf_form_requirement(self):
        response = self.client.post('/probe-json', json={'hello': 'world'})

        self.assertEqual(200, response.status_code)
        self.assertEqual({'ok': True}, response.get_json())


class Test_flaskApp_proxyFix_apply(TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.secret_key = 'testing'

        @self.app.route('/request-meta')
        def page_request_meta():
            return flask.jsonify({
                'remote_addr': flask.request.remote_addr,
                'scheme': flask.request.scheme,
                'host': flask.request.host,
            })

    def test_applies_forwarded_headers_when_trusted_hops_are_configured(self):
        flaskApp_proxyFix_apply(self.app, {
            'x_for': 1,
            'x_proto': 1,
            'x_host': 1,
        })

        response = self.app.test_client().get(
            '/request-meta',
            headers={
                'X-Forwarded-For': '203.0.113.9',
                'X-Forwarded-Proto': 'https',
                'X-Forwarded-Host': 'example.com',
            },
            environ_overrides={'REMOTE_ADDR': '10.0.0.5', 'HTTP_HOST': 'internal-proxy'},
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual('203.0.113.9', response.json['remote_addr'])
        self.assertEqual('https', response.json['scheme'])
        self.assertEqual('example.com', response.json['host'])

    def test_leaves_request_metadata_unchanged_when_disabled(self):
        flaskApp_proxyFix_apply(self.app, {'x_for': 0, 'x_proto': 0, 'x_host': 0})

        response = self.app.test_client().get(
            '/request-meta',
            headers={
                'X-Forwarded-For': '203.0.113.9',
                'X-Forwarded-Proto': 'https',
                'X-Forwarded-Host': 'example.com',
            },
            environ_overrides={'REMOTE_ADDR': '10.0.0.5', 'HTTP_HOST': 'internal-proxy'},
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual('10.0.0.5', response.json['remote_addr'])
        self.assertEqual('http', response.json['scheme'])
        self.assertEqual('internal-proxy', response.json['host'])

    def test_rejects_invalid_trusted_hop_values(self):
        with self.assertRaisesRegex(ValueError, 'Invalid ProxyFix setting'):
            flaskApp_proxyFix_apply(self.app, {'x_for': 'abc'})


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
        self.csrf_token = _csrf_token_seed(self.client)

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
        self.db.authaccounts_user_login_ip_attempts_recent_count.return_value = 0
        self.db.authsession_session_create.return_value = SimpleNamespace(
            wolc_authsession__session__id=17,
            wolc_authsession__session__cookie_id='cookie-123',
            wolc_authaccounts__user__id=5,
        )
        self.db.authaccounts_user_login_log.side_effect = RuntimeError('success log failed')

        with patch('bcrypt.checkpw', return_value=True):
            response = self.client.post('/auth/login', data={
                'csrf_token': self.csrf_token,
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
        self.db.authaccounts_user_login_ip_attempts_recent_count.return_value = 0
        self.db.authaccounts_user_login_consecutive_failures_count.return_value = 0
        self.db.authaccounts_user_login_log.side_effect = RuntimeError('failure log failed')

        with patch('pyyaul.web.auth.blueprint.time.sleep', return_value=None), \
             patch('bcrypt.checkpw', return_value=False):
            response = self.client.post('/auth/login', data={
                'csrf_token': self.csrf_token,
                'username_or_email': 'alice',
                'password': 'wrong',
            })

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.headers['Location'].endswith('/auth/login'))
        self.on_log_error.assert_called_once()
        self.assertIsInstance(self.on_log_error.call_args.args[0], RuntimeError)


class Test_BlueprintContext_passkey_offer(TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.secret_key = 'testing'
        self.db = MagicMock()
        self.blueprintContext = BlueprintContext(
            'auth',
            __name__,
            self.db,
            passkeys_enabled=True,
        )

        @self.app.route('/')
        def page_index():
            return 'index'

        self.app.register_blueprint(self.blueprintContext.blueprint)
        self.client = self.app.test_client()
        self.csrf_token = _csrf_token_seed(self.client)

    def test_password_login_redirects_to_passkey_offer_when_eligible(self):
        self.db.authaccounts_user_readByEmailOrUsername.return_value = SimpleNamespace(
            id=5,
            is_loginenabled=True,
            is_disabled=False,
            unlocked=None,
        )
        self.db.authaccounts_user_passwordHash_readByID.return_value = 'unused'
        self.db.authaccounts_loginmethod_id_readByName.return_value = 3
        self.db.authaccounts_user_login_ip_attempts_recent_count.return_value = 0
        self.db.authsession_session_create.return_value = SimpleNamespace(
            wolc_authsession__session__id=17,
            wolc_authsession__session__cookie_id='cookie-123',
            wolc_authaccounts__user__id=5,
        )
        self.db.authaccounts_user_readByID.return_value = SimpleNamespace(
            id=5,
            passkey_offer_dismissed=False,
        )
        self.db.authaccounts_passkeys_readByUserID.return_value = []

        with patch('bcrypt.checkpw', return_value=True):
            response = self.client.post('/auth/login', data={
                'csrf_token': self.csrf_token,
                'username_or_email': 'alice',
                'password': 'secret',
            })

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.headers['Location'].endswith('/auth/passkey-offer'))

    def test_passkey_offer_dismiss_sets_permanent_opt_out(self):
        self.blueprintContext._authsession_session_record_read = MagicMock(
            return_value=SimpleNamespace(
                wolc_authaccounts__user__id=7,
                wolc_authsession__session__id=11,
            )
        )
        self.db.authaccounts_user_readByID.return_value = SimpleNamespace(
            id=7,
            passkey_offer_dismissed=False,
        )
        self.db.authaccounts_passkeys_readByUserID.return_value = []

        response = self.client.post('/auth/passkey-offer', data={
            'csrf_token': self.csrf_token,
            'action': 'dismiss',
        })

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.headers['Location'].endswith('/'))
        self.db.authaccounts_user_passkey_offer_dismissed_set.assert_called_once_with(7, True)

    def test_passkey_offer_remind_later_sets_session_skip_only(self):
        self.blueprintContext._authsession_session_record_read = MagicMock(
            return_value=SimpleNamespace(
                wolc_authaccounts__user__id=7,
                wolc_authsession__session__id=11,
            )
        )
        self.db.authaccounts_user_readByID.return_value = SimpleNamespace(
            id=7,
            passkey_offer_dismissed=False,
        )
        self.db.authaccounts_passkeys_readByUserID.return_value = []

        response = self.client.post('/auth/passkey-offer', data={
            'csrf_token': self.csrf_token,
            'action': 'later',
        })

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.headers['Location'].endswith('/'))
        self.db.authaccounts_user_passkey_offer_dismissed_set.assert_not_called()
        with self.client.session_transaction() as session:
            self.assertTrue(session.get(self.blueprintContext.session_keys_passkey_offer_skip_str))


class Test_BlueprintContext_login_flow(TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.secret_key = 'testing'
        self.db = MagicMock()
        self.blueprintContext = BlueprintContext('auth', __name__, self.db)

        @self.app.route('/')
        def page_index():
            return 'index'

        self.app.register_blueprint(self.blueprintContext.blueprint)
        self.client = self.app.test_client()
        self.csrf_token = _csrf_token_seed(self.client)
        self.db.authaccounts_loginmethod_id_readByName.return_value = 3
        self.db.authaccounts_user_login_ip_attempts_recent_count.return_value = 0

    def test_ip_rate_limit_returns_429_without_user_lookup(self):
        self.db.authaccounts_user_login_ip_attempts_recent_count.return_value = _IP_RATE_MAX_ATTEMPTS

        response = self.client.post('/auth/login', data={
            'csrf_token': self.csrf_token,
            'username_or_email': 'alice',
            'password': 'secret',
        })

        self.assertEqual(429, response.status_code)
        self.assertEqual(_LOGIN_IP_RATE_LIMIT_RESPONSE_MESSAGE, response.get_data(as_text=True))
        self.db.authaccounts_user_readByEmailOrUsername.assert_not_called()
        self.db.authaccounts_user_login_log.assert_called_once()
        self.assertTrue(self.db.authaccounts_user_login_log.call_args.kwargs['loginmethod_details']['rate_limited'])

    def test_wrong_password_fifth_failure_sets_future_lockout(self):
        self.db.authaccounts_user_readByEmailOrUsername.return_value = SimpleNamespace(
            id=5,
            is_loginenabled=True,
            is_disabled=False,
            unlocked=None,
        )
        self.db.authaccounts_user_passwordHash_readByID.return_value = 'unused'
        self.db.authaccounts_user_login_consecutive_failures_count.return_value = 4
        self.db.authaccounts_user_login_lockout_count.return_value = 0

        with patch('pyyaul.web.auth.blueprint.time.sleep', return_value=None), \
             patch('bcrypt.checkpw', return_value=False):
            response = self.client.post('/auth/login', data={
                'csrf_token': self.csrf_token,
                'username_or_email': 'alice',
                'password': 'wrong',
            })

        self.assertEqual(302, response.status_code)
        self.db.authaccounts_user_unlocked_set.assert_called_once()
        unlock_at = self.db.authaccounts_user_unlocked_set.call_args.args[1]
        self.assertGreater(unlock_at, datetime.now(timezone.utc))
        self.assertEqual(
            unlock_at,
            self.db.authaccounts_user_login_log.call_args.kwargs['unlocked'],
        )

    def test_locked_account_returns_account_locked_response_without_incrementing_failures(self):
        self.db.authaccounts_user_readByEmailOrUsername.return_value = SimpleNamespace(
            id=5,
            is_loginenabled=True,
            is_disabled=False,
            unlocked=datetime.now(timezone.utc) + timedelta(minutes=5),
        )

        with patch('pyyaul.web.auth.blueprint.time.sleep', return_value=None):
            response = self.client.post('/auth/login', data={
                'csrf_token': self.csrf_token,
                'username_or_email': 'alice',
                'password': 'wrong',
            })

        self.assertEqual(423, response.status_code)
        self.assertEqual(_LOGIN_ACCOUNT_LOCKED_RESPONSE_MESSAGE, response.get_data(as_text=True))
        self.db.authaccounts_user_login_consecutive_failures_count.assert_not_called()
        self.db.authaccounts_user_unlocked_set.assert_not_called()
