"""
Module for authenticating users.
"""

from collections import deque
from datetime import datetime, timedelta, timezone
from functools import partial, wraps
from pyyaul.db.version import Version
from pyyaul.web.auth.db.model import DBModelContext
from pyyaul.db.orm import ORM
from sqlalchemy.orm import Session
from sqlalchemy.future import select
from werkzeug.security import generate_password_hash, check_password_hash
import flask
import inspect
import secrets
import logging
import threading
import time
import traceback


DEFAULT_SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'",
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
}
_REQUEST_LOGGER_NAME = 'pyyaul.web.request'
_REQUEST_START_TIME_KEY = '_pyyaul_request_start_time'


PRIVILEGE_GROUPS_PATH = ('sudo', 'groups')
PRIVILEGE_GROUPS_CREATE_PATH = ('sudo', 'groups', 'create')
PRIVILEGE_GROUPS_READ_PATH = ('sudo', 'groups', 'read')
PRIVILEGE_GROUPS_UPDATE_PATH = ('sudo', 'groups', 'update')
PRIVILEGE_GROUPS_UPDATE_NAME_PATH = ('sudo', 'groups', 'update', 'name')
PRIVILEGE_GROUPS_UPDATE_USERS_PATH = ('sudo', 'groups', 'update', 'users')
PRIVILEGE_GROUPS_UPDATE_PRIVILEGES_PATH = ('sudo', 'groups', 'update', 'privileges')
PRIVILEGE_USERS_PATH = ('sudo', 'users')
PRIVILEGE_USERS_CREATE_PATH = ('sudo', 'users', 'create')
PRIVILEGE_USERS_READ_PATH = ('sudo', 'users', 'read')
PRIVILEGE_USERS_UPDATE_PATH = ('sudo', 'users', 'update')
PRIVILEGE_USERS_DELETE_PATH = ('sudo', 'users', 'delete')
PRIVILEGE_PRIVILEGES_PATH = ('sudo', 'privileges')
PRIVILEGE_PRIVILEGES_CREATE_PATH = ('sudo', 'privileges', 'create')
PRIVILEGE_PRIVILEGES_READ_PATH = ('sudo', 'privileges', 'read')
PRIVILEGE_PRIVILEGES_UPDATE_PATH = ('sudo', 'privileges', 'update')
PRIVILEGE_PRIVILEGES_DELETE_PATH = ('sudo', 'privileges', 'delete')


def _flaskResponse_cookies_copy(source, target):
	"""Copies Set-Cookie headers from `source` to `target`."""
	for cookie in source.headers.getlist('Set-Cookie'):
		target.headers.add('Set-Cookie', cookie)


def flaskResponse_securityHeaders_set(flaskResponse, headers :dict[str, str|None]|None =None):
    """
    Applies the project's default security headers to `flaskResponse`.

    `headers` can override defaults per header name. A `None` value disables
    that header entirely. Headers already present on the response are preserved
    so route handlers can still set a custom CSP or similar policy.
    """
    resolved_headers = DEFAULT_SECURITY_HEADERS.copy()
    if headers is not None:
        resolved_headers.update(headers)
    for header_name, header_value in resolved_headers.items():
        if header_value is None or header_name in flaskResponse.headers:
            continue
        flaskResponse.headers[header_name] = header_value
    return flaskResponse


# --- Login brute-force protection ---
_LOGIN_MAX_CONSECUTIVE_FAILURES = 5
# Escalating lockout durations (minutes). Index = number of prior lockouts (capped at last entry).
_LOGIN_LOCKOUT_DURATIONS_MINUTES = [5, 30, 120, 1440]  # 5 min, 30 min, 2 hr, 24 hr
_LOGIN_FAILURE_RESPONSE_DELAY_SECONDS = 0.5

# In-memory per-IP rate limiter (sliding window). Resets on server restart.
_ip_attempt_lock = threading.Lock()
_ip_attempt_log: dict = {}   # ip (str) -> deque of UTC POSIX timestamps
_IP_RATE_WINDOW_SECONDS = 300   # 5-minute sliding window
_IP_RATE_MAX_ATTEMPTS = 20      # max login attempts per IP per window
_USER_RATE_LIMIT_RESPONSE_MESSAGE = 'Too many requests. Please try again later.'
_AUTH_POST_RATE_MAX_REQUESTS = 10
_AUTH_POST_RATE_WINDOW_SECONDS = 60


def _ip_rate_check_and_record(ip :str) ->bool:
    """
    Records this login attempt from `ip` and returns `True` if the IP is within
    the allowed rate limit, or `False` if it has exceeded it.
    """
    now_ts = datetime.now(timezone.utc).timestamp()
    cutoff = now_ts - _IP_RATE_WINDOW_SECONDS
    with _ip_attempt_lock:
        q = _ip_attempt_log.setdefault(ip, deque())
        while q and q[0] < cutoff:  # evict expired entries
            q.popleft()
        q.append(now_ts)
        return len(q) <= _IP_RATE_MAX_ATTEMPTS
# --- End login brute-force protection ---


class _UserRateLimiter:

    """In-memory per-user POST rate limiter using a sliding window."""

    def __init__(self, max_requests :int, window_seconds :float):
        if window_seconds <= 0:
            raise ValueError('ERROR: `window_seconds` must be positive.')
        self.max_requests = int(max_requests)
        self.window_seconds = float(window_seconds)
        self._records: dict[int, deque[float]] = {}
        self._lock = threading.Lock()
        self._prune_thread = threading.Thread(target=self._prune_loop, daemon=True)
        self._prune_thread.start()

    def _prune_loop(self):
        while True:
            time.sleep(self.window_seconds)
            self.prune_stale()

    def prune_stale(self, cutoff_ts :float|None =None):
        if cutoff_ts is None:
            cutoff_ts = time.time() - self.window_seconds
        with self._lock:
            for user_id, timestamps in list(self._records.items()):
                if len(timestamps) == 0 or timestamps[-1] <= cutoff_ts:
                    del self._records[user_id]

    def allow(self, user_id :int) -> bool:
        now_ts = time.time()
        cutoff_ts = now_ts - self.window_seconds
        with self._lock:
            timestamps = self._records.setdefault(int(user_id), deque())
            while timestamps and timestamps[0] <= cutoff_ts:
                timestamps.popleft()
            if len(timestamps) >= self.max_requests:
                if len(timestamps) == 0:
                    del self._records[int(user_id)]
                return False
            timestamps.append(now_ts)
            return True


_PASSWORD_SUGGESTED_ALPHABET_UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
_PASSWORD_SUGGESTED_ALPHABET_LOWER = 'abcdefghijkmnopqrstuvwxyz'
_PASSWORD_SUGGESTED_ALPHABET_DIGITS = '23456789'
_PASSWORD_SUGGESTED_ALPHABET_SYMBOLS = '!@#$%^&*()-_=+'
_PASSWORD_SUGGESTED_ALPHABET_ALL = (
    _PASSWORD_SUGGESTED_ALPHABET_UPPER
    + _PASSWORD_SUGGESTED_ALPHABET_LOWER
    + _PASSWORD_SUGGESTED_ALPHABET_DIGITS
    + _PASSWORD_SUGGESTED_ALPHABET_SYMBOLS
)


def password_suggested_generate(min_length :int) -> str:
    length = max(16, int(min_length))
    password_chars = [
        secrets.choice(_PASSWORD_SUGGESTED_ALPHABET_UPPER),
        secrets.choice(_PASSWORD_SUGGESTED_ALPHABET_LOWER),
        secrets.choice(_PASSWORD_SUGGESTED_ALPHABET_DIGITS),
        secrets.choice(_PASSWORD_SUGGESTED_ALPHABET_SYMBOLS),
    ]
    while len(password_chars) < length:
        password_chars.append(secrets.choice(_PASSWORD_SUGGESTED_ALPHABET_ALL))
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)



class BlueprintContext:

    """
    This class provides a templated Flask interface for authorization and
    session management for the auth console of a user account management
    system.

    Usage will look similar to this:

        ```
        from .db.schema.vLatest import Schema
        from pyyaul.web.auth.blueprint import BlueprintContext
        from pyyaul.web.auth.db.model import DBModelContext




        blueprintContext = BlueprintContext(
            'adminauth',
            __name__,
            DBModelContext(
                DBORM_ADMINACCOUNTS_RO,
                DBORM_ADMINACCOUNTS_RW,
                DBORM_ADMINSESSIONS_RO,
                DBORM_ADMINSESSIONS_RW,
                Schema,
            ),
        )

        blueprint = BlueprintContext.blueprint
        ```

    """

    blueprint :flask.Blueprint
    dbModelContext :DBModelContext
    session_keys_session_cookie_id_str :str  #Key used to store the user's session cookie ID in the `flask.session`.
    session_keys_user_id_str :str  #Key used to store the user's ID in the `flask.session`.

    def __init__(
            self,
            blueprint_name :str,
            blueprint_import_name :str,  #Usually `__name__` from the "blueprint.py" using this class.
            dbModelContext :DBModelContext,
            password_min_length :int =8,
            security_headers :dict[str, str|None]|None =None,
            on_log_error =None,
    ):
        self.blueprint = flask.Blueprint(
            blueprint_name,
            __name__,
            template_folder='templates',
            url_prefix=f'/{blueprint_name}',
        )
        self.session_keys_session_cookie_id_str = f'{blueprint_name}_session_cookie_id'
        self.session_keys_user_id_str = f'{blueprint_name}_session_user_id'
        self.dbModelContext = dbModelContext
        self.password_min_length = password_min_length
        self.security_headers = {} if security_headers is None else dict(security_headers)
        self.on_log_error = on_log_error
        self.blueprint.record_once(self._app_hooks_register)
        self.blueprint.after_request(self._response_security_headers_set)
        self.blueprint.route('/index', methods=['POST', 'GET'])(self.page_index)
        self.blueprint.route('/login', methods=['POST', 'GET'])(self.page_login)
        self.blueprint.route('/logout', methods=['POST', 'GET'])(self.page_logout)
        self.blueprint.route('/groupCreate', methods=['POST', 'GET'])(self.page_groupCreate)
        self.blueprint.route('/groupMembers', methods=['POST', 'GET'])(self.page_groupMembers)
        self.blueprint.route('/groupUpdate', methods=['POST', 'GET'])(self.page_groupUpdate)
        self.blueprint.route('/groupViewAll', methods=['POST', 'GET'])(self.page_groupViewAll)
        self.blueprint.route('/privilegeCreate', methods=['POST', 'GET'])(self.page_privilegeCreate)
        self.blueprint.route('/privilegeDelete', methods=['POST', 'GET'])(self.page_privilegeDelete)
        self.blueprint.route('/privilegeUpdate', methods=['POST', 'GET'])(self.page_privilegeUpdate)
        self.blueprint.route('/privilegeViewAll', methods=['POST', 'GET'])(self.page_privilegeViewAll)
        self.blueprint.route('/userCreate', methods=['POST', 'GET'])(self.page_userCreate)
        self.blueprint.route('/userDelete', methods=['POST', 'GET'])(self.page_userDelete)
        self.blueprint.route('/userUpdate', methods=['POST', 'GET'])(self.page_userUpdate)
        self.blueprint.route('/userResetPassword', methods=['POST', 'GET'])(self.page_userResetPassword)
        self.blueprint.route('/userViewAll', methods=['POST', 'GET'])(self.page_userViewAll)

    def _response_security_headers_set(self, flaskResponse):
        return flaskResponse_securityHeaders_set(flaskResponse, self.security_headers)

    def _app_hooks_register(self, setup_state):
        app = setup_state.app
        request_logging_installed = app.extensions.setdefault('pyyaul.web.request_logging', False)
        if request_logging_installed:
            return
        app.before_request(self._requestLog_start)
        app.after_request(self._requestLog_finish)
        app.extensions['pyyaul.web.request_logging'] = True

    def _requestLog_start(self):
        setattr(flask.g, _REQUEST_START_TIME_KEY, time.perf_counter())

    def _requestLog_finish(self, flaskResponse):
        start_time = getattr(flask.g, _REQUEST_START_TIME_KEY, None)
        if hasattr(flask.g, _REQUEST_START_TIME_KEY):
            delattr(flask.g, _REQUEST_START_TIME_KEY)
        if start_time is None:
            return flaskResponse
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logging.getLogger(_REQUEST_LOGGER_NAME).info(
            '%s %s %d %dms',
            flask.request.method,
            flask.request.path,
            flaskResponse.status_code,
            duration_ms,
        )
        return flaskResponse

    def _on_log_error(self, error):
        if self.on_log_error is None:
            return
        try:
            self.on_log_error(error)
        except Exception:
            logging.exception('audit log error callback failed')

    def _authaccounts_user_login_log(self, **kwargs):
        try:
            return self.dbModelContext.authaccounts_user_login_log(**kwargs)
        except Exception as e:
            self._on_log_error(e)
            logging.warning(
                'user login log write failed: user_id=%s session_id=%s is_success=%s error=%s',
                kwargs.get('user_id'),
                kwargs.get('session_id'),
                kwargs.get('is_success'),
                e,
            )
            return None

    @staticmethod
    def _authSessionRequired_static(func):
        """
        Version of `authSessionRequired` for use by this class's methods.

        Usage:
        ```
            @_authSessionRequired_static
            def page_index(self, _auth_authsession_session_record):
                if authsession_session_record is None:
                    raise ValueError('`authsession_session_record` was unexpectedly `None`.')
                # Consider the user validated. Do secure things.
                return "Secure content for authenticated users."
        ```
        """
        # assert(inspect.ismethod(func))
        @wraps(func)
        def decorated_function(self, *args, **kargs):
            assert(isinstance(self, BlueprintContext))
            return self.authSessionRequired(func, True)(self, *args, **kargs)
        return decorated_function

    def authSessionRequired(self, func, _useInternalKarg :bool =False):
        """
        Function decorator that will attempt to read the user's `authsession_session_record`
        and redirect the user to the site's login page if the session could not be
        found.

        If the session is found successfully, then the record will be passed to the
        decorated function as a `{self.blueprint.name}_authsession_session_record` keyword argument.

        Usage:
        ```
            @app.route('/aSecurePage', methods=('GET', 'POST'))
            @authSessionRequired
            def page_aSecurePage(adminauth_authsession_session_record):
                if authsession_session_record is None:
                    raise ValueError('`authsession_session_record` was unexpectedly `None`.')
                # Consider the user validated. Do secure things.
                return "Secure content for authenticated users."
        ```

        If `_useInternalKarg` is `True`, will use the keyword argument
        `_auth_authsession_session_record`.  This should only be used by methods
        of this class that don't need to differentiate between different
        module's records but DO want to be able to accept a statically-named
        keyword argument.
        """
        @wraps(func)
        def decorated_function(*args, **kargs):
            authsession_session_record = self._authsession_session_record_read()
            if authsession_session_record is None:  #No valid session; route to login page.
                flask.flash(f'Access Denied.  User must be logged in.')
                print('WARNING User is not authenticated; rerouting to login page.')
                return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_login'))
            kargs[
                '_auth_authsession_session_record'
                if _useInternalKarg else
                f'{self.blueprint.name}_authsession_session_record'
            ] = authsession_session_record
            return func(*args, **kargs)
        return decorated_function

    @staticmethod
    def _authSessionPrivilegeRequired_static(privilege_path :list[str]|str, on_log_error =None):
        """
        Version of `authSessionRequired` for use by this class's methods.

        Usage:
        ```
            @_authSessionPrivilegeRequired_static(('sudo', 'users', 'read'))
            def page_index(self, _auth_authsession_session_record):
                if authsession_session_record is None:
                    raise ValueError('`authsession_session_record` was unexpectedly `None`.')
                # Consider the user validated. Do secure things.
                return "Secure content for authenticated users."
        ```
        """
        # assert(inspect.ismethod(func))
        def decorator(func):
            @wraps(func)
            def decorated_function(self, *args, **kargs):
                assert(isinstance(self, BlueprintContext))
                return self.authSessionPrivilegeRequired(
                    privilege_path,
                    on_log_error=on_log_error,
                )(func, True)(self, *args, **kargs)
            return decorated_function
        return decorator

    @staticmethod
    def _userRateLimit_static(max_requests :int, window_seconds :float):
        """Version of `userRateLimit` for use by this class's methods."""
        def decorator(func):
            @wraps(func)
            def decorated_function(self, *args, **kargs):
                assert(isinstance(self, BlueprintContext))
                return self.userRateLimit(max_requests, window_seconds)(func, True)(self, *args, **kargs)
            return decorated_function
        return decorator

    def authSessionPrivilegeRequired(self, privilege_path :list[str]|str, on_log_error =None):
        """
        Function decorator that will only call the wrapped function if the user
        has a valid `authsession_session_record` AND has been granted the given
        `privilege_path` privilege.

        If the session is resolved successfully and the privilege allowed, then
        the record will be passed to the decorated function as a
        `{self.blueprint.name}_authsession_session_record` keyword argument.
        
        If the session is not resolved, the user will be routed to the login
        page.
        
        If the session is resolved but the privilege is not granted, the user
        will be routed to the home page.

        Usage:
        ```
            @app.route('/aSecurePage', methods=('GET', 'POST'))
            @authSessionPrivilegeRequired_static(('sudo', 'users', 'read'))')
            def page_aSecurePage(adminauth_authsession_session_record):  #`adminauth` is the name of the blueprint.
                # Consider the user validated. Do secure things.
                return "Secure content for authenticated users with the 'sudo' privilege."
        ```

        If `_useInternalKarg` is `True`, will use the keyword argument
        `_auth_authsession_session_record`.  This should only be used by methods
        of this class that don't need to differentiate between different
        module's records but DO want to be able to accept a statically-named
        keyword argument.
        """
        def decorator(func, _useInternalKarg :bool =False):
            @wraps(func)
            def decorated_function(*args, **kargs):
                authsession_session_record = self._authsession_session_record_read()
                if authsession_session_record is None:  #No valid session; route to login page.
                    flask.flash(f'Access Denied.  User must be logged in.')
                    print('WARNING User is not authenticated; rerouting to login page.')
                    return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_login'))
                if not self.dbModelContext.authaccounts_user_allowPrivilege_read(
                        authsession_session_record.wolc_authaccounts__user__id,
                        privilege_path,
                        session_id=authsession_session_record.wolc_authsession__session__id,
                        on_log_error=self.on_log_error if on_log_error is None else on_log_error,
                ):
                    flask.flash(f'Access Denied.  If you need access, ask for the privilege at `{privilege_path!r}`.')
                    print('WARNING User has not been granted access; rerouting to login page.')
                    return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_index'))
                kargs[
                    '_auth_authsession_session_record'
                    if _useInternalKarg else
                    f'{self.blueprint.name}_authsession_session_record'
                ] = authsession_session_record
                return func(*args, **kargs)
            return decorated_function
        return decorator

    def _userRateLimit_authsession_session_record_read(self, kargs :dict) ->object|None:
        authsession_session_record = kargs.get('_auth_authsession_session_record')
        if authsession_session_record is not None:
            return authsession_session_record
        authsession_session_record = kargs.get(f'{self.blueprint.name}_authsession_session_record')
        if authsession_session_record is not None:
            return authsession_session_record
        return self._authsession_session_record_read()

    def userRateLimit(self, max_requests :int, window_seconds :float):
        """
        Function decorator that limits authenticated POST requests per user
        within a sliding time window.

        GET requests always pass through. Unauthenticated requests also pass
        through unchanged so login or IP-level protections can handle them.

        Usage:
        ```
            @app.route('/account/password', methods=('POST', 'GET'))
            @authSessionRequired
            @userRateLimit(max_requests=10, window_seconds=60)
            def page_account_password(adminauth_authsession_session_record):
                ...
        ```
        """
        limiter = _UserRateLimiter(max_requests, window_seconds)

        def decorator(func, _useInternalKarg :bool =False):
            @wraps(func)
            def decorated_function(*args, **kargs):
                if flask.request.method != 'POST':
                    return func(*args, **kargs)
                authsession_session_record = self._userRateLimit_authsession_session_record_read(kargs)
                if authsession_session_record is None:
                    return func(*args, **kargs)
                user_id = getattr(authsession_session_record, 'wolc_authaccounts__user__id', None)
                if user_id is None:
                    return func(*args, **kargs)
                if not limiter.allow(int(user_id)):
                    return flask.make_response(_USER_RATE_LIMIT_RESPONSE_MESSAGE, 429)
                return func(*args, **kargs)
            return decorated_function

        return decorator

    @staticmethod
    def _privilege_name_validate(privilege_name :str) -> str:
        privilege_name = privilege_name.strip()
        if privilege_name == '':
            raise ValueError('ERROR: `privilege_name` must be non-empty.')
        if '/' in privilege_name:
            raise ValueError('ERROR: `privilege_name` may not contain `/`.')
        return privilege_name

    @staticmethod
    def _privilege_path_to_str(privilege_path :list[str]|tuple[str, ...]) -> str:
        return '/'.join(privilege_path)

    def _privilege_details_require(self, privilege_id :int) -> dict[str, object]:
        privilege_details = self.dbModelContext.authaccounts_privilege_readByID(privilege_id)
        if privilege_details is None:
            raise ValueError(f'ERROR Unable to resolve `privilege_id` to an active privilege: {privilege_id=}')
        return privilege_details

    @staticmethod
    def _group_name_validate(group_name :str) -> str:
        group_name = group_name.strip()
        if group_name == '':
            raise ValueError('ERROR: `group_name` must be non-empty.')
        return group_name

    def _group_details_require(self, group_id :int):
        group_record = self.dbModelContext.authaccounts_group_readByID(
            group_id,
            ('id', 'username', 'created', 'name_display', 'email', 'phone_sms', 'is_group', 'is_disabled', 'is_loginenabled'),
        )
        if group_record is None:
            raise ValueError(f'ERROR Unable to resolve `group_id` to an active group: {group_id=}')
        return group_record

    @_authSessionPrivilegeRequired_static(PRIVILEGE_GROUPS_READ_PATH)
    @_authSessionPrivilegeRequired_static(PRIVILEGE_GROUPS_CREATE_PATH)
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_groupCreate(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        if flask.request.method == 'POST':
            try:
                group_name = self._group_name_validate(flask.request.form.get('group_name', ''))
                group_display_name = flask.request.form.get('group_display_name')
                self.dbModelContext.authaccounts_group_create(
                    username=group_name,
                    name_display=group_display_name,
                    creator_user_id=_auth_authsession_session_record.wolc_authaccounts__user__id,
                )
            except Exception as exc:
                traceback.print_exc()
                flask.flash(str(exc))
                flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_groupCreate'))
            else:
                flask.flash(f'Group successfully created: `{group_name}`')
                flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_groupViewAll'))
        else:
            flaskResponse.data = flask.render_template(
                'auth/groupUpdate.html',
                authsession_session_record=_auth_authsession_session_record,
                authaccounts_group_record=None,
                authaccounts_group_privilege_rules=[],
                authaccounts_privileges_sorted=[],
                group_name_update_allow=False,
                group_privileges_update_allow=False,
                isCreateMode=True,
                urlCancel=flask.url_for(f'{self.blueprint.name}.page_groupViewAll'),
                urlPost=flask.url_for(f'{self.blueprint.name}.page_groupCreate'),
            )
        return flaskResponse

    @_authSessionPrivilegeRequired_static(PRIVILEGE_GROUPS_READ_PATH)
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_groupMembers(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        caller_user_id = _auth_authsession_session_record.wolc_authaccounts__user__id
        group_users_update_allow = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id,
            PRIVILEGE_GROUPS_UPDATE_USERS_PATH,
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        try:
            targetGroup_id = int((flask.request.args if flask.request.method == 'GET' else flask.request.form)['group_id'])
            targetGroupRecord = self._group_details_require(targetGroup_id)
        except Exception:
            traceback.print_exc()
            targetGroup_id = None
            targetGroupRecord = None
        if targetGroup_id is None or targetGroupRecord is None:
            flask.flash('ERROR: `group_id` must be provided to view group members.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_groupViewAll'))
        elif flask.request.method == 'POST':
            try:
                if not group_users_update_allow:
                    raise ValueError('Access denied. This account may not update group memberships.')
                member_user_ids = flask.request.form.getlist('member_user_id')
                if len(member_user_ids) == 0:
                    raise ValueError('Please select at least one member to remove.')
                for member_user_id in member_user_ids:
                    self.dbModelContext.authaccounts_group_membership_remove(
                        targetGroup_id,
                        int(member_user_id),
                        caller_user_id,
                    )
                flask.flash('Selected members removed from the group.')
            except Exception as exc:
                traceback.print_exc()
                flask.flash(str(exc))
            flaskResponse = flask.redirect(
                flask.url_for(f'{self.blueprint.name}.page_groupMembers', group_id=targetGroup_id)
            )
        else:
            flaskResponse.data = flask.render_template(
                'auth/groupMembers.html',
                authsession_session_record=_auth_authsession_session_record,
                authaccounts_group_record=targetGroupRecord,
                authaccounts_group_members=self.dbModelContext.authaccounts_group_members_read(targetGroup_id),
                group_users_update_allow=group_users_update_allow,
                urlCancel=flask.url_for(f'{self.blueprint.name}.page_groupViewAll'),
                urlPost=flask.url_for(f'{self.blueprint.name}.page_groupMembers'),
            )
        return flaskResponse

    @_authSessionPrivilegeRequired_static(PRIVILEGE_GROUPS_READ_PATH)
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_groupUpdate(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        caller_user_id = _auth_authsession_session_record.wolc_authaccounts__user__id
        group_name_update_allow = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id,
            PRIVILEGE_GROUPS_UPDATE_NAME_PATH,
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        group_privileges_update_allow = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id,
            PRIVILEGE_GROUPS_UPDATE_PRIVILEGES_PATH,
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        mode = flask.request.args.get('mode', flask.request.form.get('mode', 'rename')).strip().lower()
        if mode not in ('rename', 'privileges'):
            mode = 'rename'
        try:
            targetGroup_id = int((flask.request.args if flask.request.method == 'GET' else flask.request.form)['group_id'])
            targetGroupRecord = self._group_details_require(targetGroup_id)
        except Exception:
            traceback.print_exc()
            targetGroup_id = None
            targetGroupRecord = None
        if targetGroup_id is None or targetGroupRecord is None:
            flask.flash('ERROR: `group_id` must be provided to edit group details.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_groupViewAll'))
        elif mode == 'rename' and not group_name_update_allow:
            flask.flash('Access denied. This account may not rename groups.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_groupViewAll'))
        elif mode == 'privileges' and not group_privileges_update_allow:
            flask.flash('Access denied. This account may not update group privilege rules.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_groupViewAll'))
        elif flask.request.method == 'POST':
            action = flask.request.form.get('action')
            try:
                if action == 'rename':
                    group_name = self._group_name_validate(flask.request.form.get('group_name', ''))
                    group_display_name = flask.request.form.get('group_display_name')
                    self.dbModelContext.authaccounts_group_update(
                        targetGroup_id,
                        group_name,
                        group_display_name,
                    )
                    flask.flash(f'Group successfully updated: `{group_name}`')
                elif action == 'add_privilege_rule':
                    privilege_path_str = flask.request.form.get('privilege_path', '').strip()
                    if privilege_path_str == '':
                        raise ValueError('ERROR: A privilege path must be selected.')
                    privilege_id = self.dbModelContext.authaccounts_privilege_read(tuple(privilege_path_str.split('/')))
                    if privilege_id is None:
                        raise ValueError(f'ERROR Unable to resolve privilege path: {privilege_path_str!r}')
                    allow = flask.request.form.get('allow', 'allow') == 'allow'
                    self.dbModelContext.authaccounts_group_privilege_rule_set(
                        targetGroup_id,
                        privilege_id,
                        allow,
                        caller_user_id,
                    )
                    flask.flash(f'Privilege rule saved for `{targetGroupRecord.username}`: `{privilege_path_str}`')
                elif action == 'remove_privilege_rule':
                    privilege_id = int(flask.request.form['privilege_id'])
                    privilege_details = self._privilege_details_require(privilege_id)
                    self.dbModelContext.authaccounts_group_privilege_rule_delete(
                        targetGroup_id,
                        privilege_id,
                        caller_user_id,
                    )
                    flask.flash(
                        f"Privilege rule removed from `{targetGroupRecord.username}`: `{privilege_details['path_str']}`"
                    )
                else:
                    raise ValueError(f'ERROR Unexpected group update action: {action!r}')
            except Exception as exc:
                traceback.print_exc()
                flask.flash(str(exc))
            flaskResponse = flask.redirect(
                flask.url_for(
                    f'{self.blueprint.name}.page_groupUpdate',
                    group_id=targetGroup_id,
                    mode=mode,
                )
            )
        else:
            authaccounts_group_privilege_rules = self.dbModelContext.authaccounts_group_privilege_rules_read(targetGroup_id)
            authaccounts_privileges_sorted = sorted(
                self.dbModelContext.authaccounts_privileges_read().values(),
                key=lambda item: tuple(item['path']),
            )
            flaskResponse.data = flask.render_template(
                'auth/groupUpdate.html',
                authsession_session_record=_auth_authsession_session_record,
                authaccounts_group_record=targetGroupRecord,
                authaccounts_group_privilege_rules=authaccounts_group_privilege_rules,
                authaccounts_privileges_sorted=authaccounts_privileges_sorted,
                group_name_update_allow=group_name_update_allow,
                group_privileges_update_allow=group_privileges_update_allow,
                group_mode=mode,
                isCreateMode=False,
                urlCancel=flask.url_for(f'{self.blueprint.name}.page_groupViewAll'),
                urlPost=flask.url_for(f'{self.blueprint.name}.page_groupUpdate'),
            )
        return flaskResponse

    @_authSessionPrivilegeRequired_static(PRIVILEGE_GROUPS_READ_PATH)
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_groupViewAll(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        caller_user_id = _auth_authsession_session_record.wolc_authaccounts__user__id
        group_create_allow = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id,
            PRIVILEGE_GROUPS_CREATE_PATH,
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        group_name_update_allow = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id,
            PRIVILEGE_GROUPS_UPDATE_NAME_PATH,
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        group_users_update_allow = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id,
            PRIVILEGE_GROUPS_UPDATE_USERS_PATH,
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        group_privileges_update_allow = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id,
            PRIVILEGE_GROUPS_UPDATE_PRIVILEGES_PATH,
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        if flask.request.method == 'POST':
            action = flask.request.form.get('action')
            group_id = flask.request.form.get('group_id')
            try:
                if action == 'create':
                    flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_groupCreate'))
                elif action == 'rename':
                    if group_id is None:
                        raise ValueError('ERROR Missing `group_id` for group rename action.')
                    flaskResponse = flask.redirect(
                        flask.url_for(f'{self.blueprint.name}.page_groupUpdate', group_id=group_id, mode='rename')
                    )
                elif action == 'privileges':
                    if group_id is None:
                        raise ValueError('ERROR Missing `group_id` for group privilege action.')
                    flaskResponse = flask.redirect(
                        flask.url_for(f'{self.blueprint.name}.page_groupUpdate', group_id=group_id, mode='privileges')
                    )
                elif action == 'members':
                    if group_id is None:
                        raise ValueError('ERROR Missing `group_id` for group members action.')
                    flaskResponse = flask.redirect(
                        flask.url_for(f'{self.blueprint.name}.page_groupMembers', group_id=group_id)
                    )
                else:
                    raise ValueError(f'Action failed; unexpected action: {action!r}')
            except Exception as exc:
                traceback.print_exc()
                flask.flash(str(exc))
                flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_groupViewAll'))
        else:
            group_records = sorted(
                self.dbModelContext.authaccounts_groups_read(),
                key=lambda record: record.username,
            )
            flaskResponse.data = flask.render_template(
                'auth/groupViewAll.html',
                authaccounts_groups_records=group_records,
                authsession_session_record=_auth_authsession_session_record,
                group_create_allow=group_create_allow,
                group_name_update_allow=group_name_update_allow,
                group_users_update_allow=group_users_update_allow,
                group_privileges_update_allow=group_privileges_update_allow,
            )
        return flaskResponse

    @_authSessionRequired_static
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_index(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        return flaskResponse

    def page_login(self):
        flaskResponse = flask.make_response()
        if flask.request.method == 'POST':  #User provided login details.
            # --- IP rate limiting (distributed brute-force mitigation) ---
            client_ip = flask.request.remote_addr or ''
            if not _ip_rate_check_and_record(client_ip):
                flask.flash('Too many login attempts from your network. Please wait a few minutes before trying again.')
                return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_login'))

            now_utc = datetime.now(timezone.utc)
            user_record = None
            passwordMatched = False
            try:
                user_record = self.dbModelContext.authaccounts_user_readByEmailOrUsername(
                    flask.request.form['username_or_email'],
                    ('id', 'is_loginenabled', 'is_disabled', 'unlocked'),
                )
            except KeyError:  #User didn't provide username in the form.
                pass
            except ValueError:  #User record could not be found.
                pass
            else:
                if not user_record.is_loginenabled:
                    user_record = None  #Group/automation account — treat as not found.
                elif user_record.is_disabled:
                    pass  #Disabled account; passwordMatched stays False.
                elif user_record.unlocked is not None and user_record.unlocked > now_utc:
                    pass  #Account still locked; don't increment the failure counter.
                else:
                    try:
                        passwordHash = self.dbModelContext.authaccounts_user_passwordHash_readByID(
                            user_record.id
                        )
                    except ValueError:
                        pass  #No password on file; passwordMatched stays False.
                    else:  #Validate the password.
                        import bcrypt
                        try:
                            passwordMatched = bcrypt.checkpw(
                                flask.request.form['password'].encode('utf-8'),
                                passwordHash.encode('utf-8'),
                            )
                        except KeyError:  #User didn't provide password in the form.
                            passwordMatched = False

            # Fetch the loginmethod ID once for audit logging.
            try:
                loginmethod_id = self.dbModelContext.authaccounts_loginmethod_id_readByName(
                    self.dbModelContext.dbSchema.LoginMethod.Password.value
                )
            except ValueError:
                loginmethod_id = None

            already_locked = (
                user_record is not None
                and user_record.unlocked is not None
                and user_record.unlocked > now_utc
            )

            login_details = {
                'ip': flask.request.remote_addr,
                'user_agent': flask.request.user_agent.string,
            }

            if user_record is not None and passwordMatched:  #User has been authenticated.
                persistCookies = True if (flask.request.form.get('persistCookies') == 'yes') else False
                authsession_session_record = self.dbModelContext.authsession_session_create(user_record.id)
                if loginmethod_id is not None:
                    self._authaccounts_user_login_log(
                        loginmethod_id=loginmethod_id,
                        is_success=True,
                        user_id=user_record.id,
                        session_id=authsession_session_record.wolc_authsession__session__id,
                        loginmethod_details=login_details,
                    )
                flask.session.permanent = persistCookies
                flask.session[self.session_keys_session_cookie_id_str] = authsession_session_record.wolc_authsession__session__cookie_id
                flask.session[self.session_keys_user_id_str] = authsession_session_record.wolc_authaccounts__user__id
                flaskResponseOld = flaskResponse
                flaskResponse = flask.redirect(flask.url_for(f'page_index'))  #Route to root, which routes logged-in users to a suitable landing page.
                _flaskResponse_cookies_copy(flaskResponseOld, flaskResponse)
            else:  #Authentication failed.
                time.sleep(_LOGIN_FAILURE_RESPONSE_DELAY_SECONDS)

                # Determine whether this failure should trigger a lockout.
                lockout_unlocked_at = None
                if user_record is not None and not already_locked:
                    consecutive_failures = (
                        self.dbModelContext.authaccounts_user_login_consecutive_failures_count(user_record.id) + 1
                    )
                    if consecutive_failures >= _LOGIN_MAX_CONSECUTIVE_FAILURES:
                        lockout_count = self.dbModelContext.authaccounts_user_login_lockout_count(user_record.id)
                        durations = _LOGIN_LOCKOUT_DURATIONS_MINUTES
                        duration_minutes = durations[min(lockout_count, len(durations) - 1)]
                        lockout_unlocked_at = now_utc + timedelta(minutes=duration_minutes)
                        self.dbModelContext.authaccounts_user_unlocked_set(user_record.id, lockout_unlocked_at)

                if loginmethod_id is not None:
                    self._authaccounts_user_login_log(
                        loginmethod_id=loginmethod_id,
                        is_success=False,
                        user_id=user_record.id if user_record is not None else None,
                        unlocked=lockout_unlocked_at,
                        loginmethod_details=login_details,
                    )

                flask.flash('The provided login details could not be verified.  Please check your login details and try again.')
                flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_login'))
        else:  #User either has an active session or needs to be taken to the login form.
            try:
                authsession_session_record = self.dbModelContext.authsession_session_readByCookieID(
                    flask.session[self.session_keys_session_cookie_id_str]
                )
                assert(
                    authsession_session_record.wolc_authaccounts__user__id
                    == flask.session[self.session_keys_user_id_str]
                )
            except (KeyError, ValueError):  #User is not logged in; show them to the login form.
                flaskResponse.data = flask.render_template(
                    'auth/login.html',
                    urlPost=flask.url_for(f'{self.blueprint.name}.page_login'),
                )
            else:  #User has an active session.
                flaskResponse = flask.redirect(flask.url_for(f'page_index'))  #Route to root, which routes logged-in users to a suitable landing page.
        return flaskResponse

    @_authSessionRequired_static
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_logout(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        self.dbModelContext.authsession_session_deleteByID(
            _auth_authsession_session_record.wolc_authsession__session__id
        )
        flaskResponse.data = flask.render_template('auth/logout_success.html')
        return flaskResponse

    @_authSessionPrivilegeRequired_static(PRIVILEGE_PRIVILEGES_READ_PATH)
    @_authSessionPrivilegeRequired_static(PRIVILEGE_PRIVILEGES_CREATE_PATH)
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_privilegeCreate(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        try:
            privilege_parent_id = int((flask.request.args if flask.request.method == 'GET' else flask.request.form)['privilege_parent_id'])
            authaccounts_privilege_parent_details = self._privilege_details_require(privilege_parent_id)
        except Exception:
            traceback.print_exc()
            authaccounts_privilege_parent_details = None
            privilege_parent_id = None
        if privilege_parent_id is None or authaccounts_privilege_parent_details is None:
            flask.flash('ERROR: A valid `privilege_parent_id` must be provided to create a new privilege.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'))
        elif flask.request.method == 'POST':
            try:
                form_parent_id = int(flask.request.form['privilege_parent_id'])
                if form_parent_id != privilege_parent_id:
                    raise ValueError('ERROR: `privilege_parent_id` mismatch; create operation aborted.')
                privilege_name = self._privilege_name_validate(flask.request.form.get('privilege_name', ''))
                self.dbModelContext.authaccounts_privilege_create(
                    creator_user_id=_auth_authsession_session_record.wolc_authaccounts__user__id,
                    name=privilege_name,
                    parent_id=privilege_parent_id,
                )
            except Exception as exc:
                traceback.print_exc()
                flask.flash(str(exc))
            else:
                flask.flash(
                    f"Privilege successfully created: `{self._privilege_path_to_str((*authaccounts_privilege_parent_details['path'], privilege_name))}`"
                )
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'))
        else:
            flaskResponse.data = flask.render_template(
                'auth/privilegeUpdate.html',
                authaccounts_privilege_details=None,
                authaccounts_privilege_parent_details=authaccounts_privilege_parent_details,
                authsession_session_record=_auth_authsession_session_record,
                privilege_path_preview=f"{authaccounts_privilege_parent_details['path_str']}/...",
                urlCancel=flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'),
                urlPost=flask.url_for(f'{self.blueprint.name}.page_privilegeCreate'),
            )
        return flaskResponse

    @_authSessionPrivilegeRequired_static(PRIVILEGE_PRIVILEGES_DELETE_PATH)
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_privilegeDelete(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        try:
            targetPrivilege_id = int((flask.request.args if flask.request.method == 'GET' else flask.request.form)['privilege_id'])
            targetPrivilege_details = self._privilege_details_require(targetPrivilege_id)
        except Exception:
            traceback.print_exc()
            targetPrivilege_details = None
            targetPrivilege_id = None
        if targetPrivilege_id is None or targetPrivilege_details is None:
            flask.flash('ERROR: `privilege_id` must be provided for delete operations.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'))
        elif targetPrivilege_details['record'].parent_id is None:
            flask.flash('ERROR: The root privilege cannot be deleted.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'))
        elif flask.request.method == 'POST':
            if flask.request.form.get('user_confirmed_delete', 'no') != 'yes':
                flask.flash('Delete operation cancelled.')
            else:
                try:
                    self.dbModelContext.authaccounts_privilege_delete(
                        targetPrivilege_id,
                        _auth_authsession_session_record.wolc_authaccounts__user__id,
                    )
                except Exception as exc:
                    traceback.print_exc()
                    flask.flash(str(exc))
                else:
                    flask.flash(
                        f"Privilege subtree successfully deleted: `{targetPrivilege_details['path_str']}`"
                    )
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'))
        else:
            flaskResponse.data = flask.render_template(
                'auth/privilegeDelete.html',
                authsession_session_record=_auth_authsession_session_record,
                targetPrivilege_details=targetPrivilege_details,
                urlCancel=flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'),
                urlPost=flask.url_for(f'{self.blueprint.name}.page_privilegeDelete'),
            )
        return flaskResponse

    @_authSessionPrivilegeRequired_static(PRIVILEGE_PRIVILEGES_UPDATE_PATH)
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_privilegeUpdate(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        try:
            targetPrivilege_id = int((flask.request.args if flask.request.method == 'GET' else flask.request.form)['privilege_id'])
            targetPrivilege_details = self._privilege_details_require(targetPrivilege_id)
        except Exception:
            traceback.print_exc()
            targetPrivilege_details = None
            targetPrivilege_id = None
        if targetPrivilege_id is None or targetPrivilege_details is None:
            flask.flash('ERROR: `privilege_id` must be provided to edit a privilege.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'))
        elif targetPrivilege_details['record'].parent_id is None:
            flask.flash('ERROR: The root privilege cannot be renamed.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'))
        elif flask.request.method == 'POST':
            try:
                form_privilege_id = int(flask.request.form['privilege_id'])
                if form_privilege_id != targetPrivilege_id:
                    raise ValueError('ERROR: `privilege_id` mismatch; update operation aborted.')
                privilege_name = self._privilege_name_validate(flask.request.form.get('privilege_name', ''))
                self.dbModelContext.authaccounts_privilege_update(targetPrivilege_id, privilege_name)
            except Exception as exc:
                traceback.print_exc()
                flask.flash(str(exc))
            else:
                updated_path = (*targetPrivilege_details['path'][:-1], privilege_name)
                flask.flash(f"Privilege successfully updated: `{self._privilege_path_to_str(updated_path)}`")
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'))
        else:
            authaccounts_privilege_parent_details = self._privilege_details_require(targetPrivilege_details['record'].parent_id)
            flaskResponse.data = flask.render_template(
                'auth/privilegeUpdate.html',
                authaccounts_privilege_details=targetPrivilege_details,
                authaccounts_privilege_parent_details=authaccounts_privilege_parent_details,
                authsession_session_record=_auth_authsession_session_record,
                privilege_path_preview=targetPrivilege_details['path_str'],
                urlCancel=flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'),
                urlPost=flask.url_for(f'{self.blueprint.name}.page_privilegeUpdate'),
            )
        return flaskResponse

    @_authSessionPrivilegeRequired_static(PRIVILEGE_PRIVILEGES_READ_PATH)
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_privilegeViewAll(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        if flask.request.method == 'POST':
            errMsg = None
            action = flask.request.form.get('action')
            privilege_id = flask.request.form.get('privilege_id')
            if None in (action, privilege_id):
                errMsg = 'Action failed; missing expected POST form contents.'
                flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'))
            elif action == 'create_subprivilege':
                flaskResponse = flask.redirect(
                    flask.url_for(
                        f'{self.blueprint.name}.page_privilegeCreate',
                        privilege_parent_id=privilege_id,
                    )
                )
            elif action == 'delete':
                flaskResponse = flask.redirect(
                    flask.url_for(
                        f'{self.blueprint.name}.page_privilegeDelete',
                        privilege_id=privilege_id,
                    )
                )
            elif action == 'update':
                flaskResponse = flask.redirect(
                    flask.url_for(
                        f'{self.blueprint.name}.page_privilegeUpdate',
                        privilege_id=privilege_id,
                    )
                )
            else:
                errMsg = f'Action failed; unexpected action: {action=}'
            if errMsg is not None:
                flask.flash(errMsg)
                flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_privilegeViewAll'))
        else:
            caller_user_id = _auth_authsession_session_record.wolc_authaccounts__user__id
            privilege__privilege_create_allow = self.dbModelContext.authaccounts_user_allowPrivilege_read(
                caller_user_id,
                PRIVILEGE_PRIVILEGES_CREATE_PATH,
                session_id=_auth_authsession_session_record.wolc_authsession__session__id,
            )
            privilege__privilege_update_allow = self.dbModelContext.authaccounts_user_allowPrivilege_read(
                caller_user_id,
                PRIVILEGE_PRIVILEGES_UPDATE_PATH,
                session_id=_auth_authsession_session_record.wolc_authsession__session__id,
            )
            privilege__privilege_delete_allow = self.dbModelContext.authaccounts_user_allowPrivilege_read(
                caller_user_id,
                PRIVILEGE_PRIVILEGES_DELETE_PATH,
                session_id=_auth_authsession_session_record.wolc_authsession__session__id,
            )
            authaccounts_privileges_sorted = sorted(
                self.dbModelContext.authaccounts_privileges_read().values(),
                key=lambda item: tuple(item['path']),
            )
            flaskResponse.data = flask.render_template(
                'auth/privilegeViewAll.html',
                authaccounts_privileges_sorted=authaccounts_privileges_sorted,
                authsession_session_record=_auth_authsession_session_record,
                privilege__privilege_create_allow=privilege__privilege_create_allow,
                privilege__privilege_delete_allow=privilege__privilege_delete_allow,
                privilege__privilege_update_allow=privilege__privilege_update_allow,
            )
        return flaskResponse

    @_authSessionRequired_static
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_userCreate(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        caller_is_super_auth = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            _auth_authsession_session_record.wolc_authaccounts__user__id, ('sudo',),
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        if not caller_is_super_auth:
            flask.flash('Must log in with a super-auth account to create new administrator accounts.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        elif flask.request.method == 'POST':  #Authorized 'POST' operation.
            errMsg = None
            username = flask.request.form.get('username')
            if username is None:
                errMsg = 'ERROR: Username must be provided; create operation aborted.'
            if errMsg is None:
                from .model import authAccountsRecord_make
                authaccounts_users_record = None
                try:
                    authaccounts_users_record = authAccountsRecord_make(
                        self.dbModelContext,
                        _auth_authsession_session_record,
                        username=username,
                        is_super_auth=flask.request.form.get('is_super_auth', 'no') == 'yes',
                        email=flask.request.form.get('email'),
                        name=flask.request.form.get('name'),
                        phone_sms=flask.request.form.get('phone_sms'),
                    )
                except Exception:
                    traceback.print_exc()
                    errMsg = 'ERROR: Failed to create new user record.'
                if errMsg is None:
                    if authaccounts_users_record is None:
                        errMsg = 'ERROR: FAILED to create new user record.'
                    else:
                        userID = authaccounts_users_record.id
            if errMsg is None:
                flaskResponse = flask.redirect(flask.url_for(
                    f'{self.blueprint.name}.page_userResetPassword',
                    user_id=userID,
                ))
            else:
                flask.flash(errMsg)
                flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        else:  #Authorized 'GET' operation.
            flaskResponse.data = flask.render_template(
                'auth/userUpdate.html',
                targetUserRecord=None,  #`None` signals "create" mode to the template.
                authsession_session_record=_auth_authsession_session_record,
                caller_is_super_auth=caller_is_super_auth,
                target_is_super_auth=False,
                urlCancel=flask.url_for(f'{self.blueprint.name}.page_userViewAll'),
                urlPost=flask.url_for(f'{self.blueprint.name}.page_userCreate'),
            )
        return flaskResponse

    @_authSessionRequired_static
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_userDelete(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        try:
            targetUser_id = int((flask.request.args if flask.request.method == 'GET' else flask.request.form)['user_id'])
        except:
            traceback.print_exc()
            targetUser_id = None
        caller_is_super_auth = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            _auth_authsession_session_record.wolc_authaccounts__user__id, ('sudo',),
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        if targetUser_id is None:
            flask.flash(f'ERROR: `user_id` must be provided for delete operations: ({targetUser_id=}).')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        elif not caller_is_super_auth:  #Only super-auth accounts are allowed to delete records.
            flask.flash('Only a super-auth account may delete other accounts.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        elif flask.request.method == 'POST':  #Authorized 'POST' operation.
            from .model import authAccountsRecord_delete
            try:
                authAccountsRecord_delete(
                    self.dbModelContext,
                    _auth_authsession_session_record,
                    targetUser_id,
                )
                flask.flash('Account successfully deleted.')
            except Exception:
                traceback.print_exc()
                flask.flash('ERROR: Failed to delete account.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        else:  #Authorized 'GET' operation.
            targetUserRecord = self.dbModelContext.authaccounts_user_readByID(
                targetUser_id, ('id', 'username', 'created')
            )
            flaskResponse.data = flask.render_template(
                'auth/userDelete.html',
                authsession_session_record=_auth_authsession_session_record,
                targetUserRecord=targetUserRecord,
                caller_is_super_auth=caller_is_super_auth,
                urlCancel=flask.url_for(f'{self.blueprint.name}.page_userViewAll'),
                urlPost=flask.url_for(f'{self.blueprint.name}.page_userDelete'),
            )
        return flaskResponse

    @_authSessionRequired_static
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_userUpdate(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        try:
            targetUser_id = int((flask.request.args if flask.request.method == 'GET' else flask.request.form)['user_id'])
        except Exception:
            traceback.print_exc()
            targetUser_id = None
        caller_user_id = _auth_authsession_session_record.wolc_authaccounts__user__id
        caller_is_super_auth = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id, ('sudo',),
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        group_users_update_allow = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id,
            PRIVILEGE_GROUPS_UPDATE_USERS_PATH,
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        caller_can_edit_user_info = (
            caller_is_super_auth
            or targetUser_id == _auth_authsession_session_record.wolc_authaccounts__user__id
        )
        if targetUser_id is None:
            flask.flash(f'ERROR: `user_id` must be provided to edit account details ({targetUser_id=}).')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        elif (not caller_can_edit_user_info) and (not group_users_update_allow):
            flask.flash('This account may only be edited by a super-auth, the account itself, or an administrator with group-membership update access.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        elif flask.request.method == 'POST':
            action = flask.request.form.get('action', 'update_info')
            if action == 'add_group_membership':
                if not group_users_update_allow:
                    flask.flash('Access denied. This account may not update group memberships.')
                else:
                    try:
                        group_name = self._group_name_validate(flask.request.form.get('group_name', ''))
                        targetGroupRecord = self.dbModelContext.authaccounts_group_readByUsername(
                            group_name,
                            ('id', 'username'),
                        )
                        self.dbModelContext.authaccounts_group_membership_add(
                            targetGroupRecord.id,
                            targetUser_id,
                            caller_user_id,
                        )
                        flask.flash(f'Added `{self.dbModelContext.authaccounts_user_readByID(targetUser_id, ("username",)).username}` to group `{targetGroupRecord.username}`.')
                    except Exception as exc:
                        traceback.print_exc()
                        flask.flash(str(exc))
                flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userUpdate', user_id=targetUser_id))
            else:
                if not caller_can_edit_user_info:
                    flask.flash("This account's information may only be edited by a super-auth or by logging in to the account itself.")
                else:
                    from .model import authAccountsRecord_info_set
                    try:
                        authAccountsRecord_info_set(
                            self.dbModelContext,
                            _auth_authsession_session_record,
                            targetUser_id,
                            flask.request.form.get('name'),
                            flask.request.form.get('email'),
                            flask.request.form.get('phone_sms'),
                        )
                        flask.flash('Account information successfully changed.')
                    except Exception:
                        traceback.print_exc()
                        flask.flash('ERROR: Failed to update account information.')
                flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        else:
            targetUserRecord = self.dbModelContext.authaccounts_user_readByID(
                targetUser_id, ('id', 'username', 'created', 'name_display', 'email', 'phone_sms', 'is_group')
            )
            current_group_memberships = self.dbModelContext.authaccounts_user_group_memberships_read(targetUser_id)
            target_is_sudoer = any(item['group_username'] == 'sudoers' for item in current_group_memberships)
            existing_group_ids = {item['group_id'] for item in current_group_memberships}
            available_group_records = [
                group_record
                for group_record in sorted(self.dbModelContext.authaccounts_groups_read(), key=lambda record: record.username)
                if group_record.id not in existing_group_ids and group_record.id != targetUser_id
            ]
            flaskResponse.data = flask.render_template(
                'auth/userUpdate.html',
                authsession_session_record=_auth_authsession_session_record,
                targetUserRecord=targetUserRecord,
                caller_is_super_auth=caller_is_super_auth,
                caller_can_edit_user_info=caller_can_edit_user_info,
                group_users_update_allow=group_users_update_allow,
                target_is_sudoer=target_is_sudoer,
                target_is_group=targetUserRecord.is_group,
                current_group_memberships=current_group_memberships,
                available_group_records=available_group_records,
                urlCancel=flask.url_for(f'{self.blueprint.name}.page_userViewAll'),
                urlPost=flask.url_for(f'{self.blueprint.name}.page_userUpdate'),
            )
        return flaskResponse

    @_authSessionRequired_static
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_userResetPassword(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        try:
            targetUser_id = int((flask.request.args if flask.request.method == 'GET' else flask.request.form)['user_id'])
        except:
            traceback.print_exc()
            targetUser_id = None
        caller_is_super_auth = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            _auth_authsession_session_record.wolc_authaccounts__user__id, ('sudo',),
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        if targetUser_id is None:
            flask.flash(f'`user_id` must be provided to reset a password ({targetUser_id=}).')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        elif (
                not caller_is_super_auth  #Super-auth accounts are allowed to reset any password.
                and targetUser_id != _auth_authsession_session_record.wolc_authaccounts__user__id  #Users are allowed to reset their own password.
        ):
            flask.flash('This account\'s password may only be changed by a super-auth or by logging in to the account itself.')
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        elif flask.request.method == 'POST':  #Authorized 'POST' operation.
            errMsg = None
            password = flask.request.form.get('password')
            passwordConfirm = flask.request.form.get('passwordConfirm')
            if None in (password, passwordConfirm):
                errMsg = 'Missing form data; POST operation aborted.'
            elif password != passwordConfirm:
                errMsg = 'Passwords do not match.'
            if errMsg is None:
                from .model import authAccountsRecord_password_set
                try:
                    authAccountsRecord_password_set(
                        self.dbModelContext,
                        targetUser_id,
                        password=password,
                        min_length=self.password_min_length,
                    )
                    flask.flash('Password successfully changed.')
                except Exception:
                    traceback.print_exc()
                    errMsg = 'ERROR: Failed to set password.'
            if errMsg is not None:
                flask.flash(errMsg)
            flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        else:  #Authorized 'GET' operation.
            targetUserRecord = self.dbModelContext.authaccounts_user_readByID(
                targetUser_id, ('id', 'username')
            )
            flaskResponse.data = flask.render_template(
                'auth/userResetPassword.html',
                targetUserRecord=targetUserRecord,
                authsession_session_record=_auth_authsession_session_record,
                passwordMinLength=self.password_min_length,
                suggestedPassword=password_suggested_generate(self.password_min_length),
                urlCancel=flask.url_for(f'{self.blueprint.name}.page_userViewAll'),
                urlPost=flask.url_for(f'{self.blueprint.name}.page_userResetPassword'),
            )
        return flaskResponse

    @_authSessionRequired_static
    @_userRateLimit_static(_AUTH_POST_RATE_MAX_REQUESTS, _AUTH_POST_RATE_WINDOW_SECONDS)
    def page_userViewAll(self, _auth_authsession_session_record):
        flaskResponse = flask.make_response()
        caller_user_id = _auth_authsession_session_record.wolc_authaccounts__user__id
        caller_is_super_auth = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id, ('sudo',),
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        group_users_update_allow = self.dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id,
            PRIVILEGE_GROUPS_UPDATE_USERS_PATH,
            session_id=_auth_authsession_session_record.wolc_authsession__session__id,
        )
        if not caller_is_super_auth and not group_users_update_allow:
            flask.flash('Access denied. This account may not view administrator accounts.')
            return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_index'))
        if flask.request.method == 'POST':
            errMsg = None
            action = flask.request.form.get('action')
            userID = flask.request.form.get('user_id')
            if None in (action, userID):
                errMsg = 'Action failed; missing POST form contents.'
                flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
            else:
                if action == 'update':
                    flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userUpdate', user_id=userID))
                elif action == 'resetPassword':
                    if not caller_is_super_auth:
                        errMsg = 'Action failed; password resets require super-auth access.'
                    else:
                        flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userResetPassword', user_id=userID))
                elif action == 'delete':
                    if not caller_is_super_auth:
                        errMsg = 'Action failed; deleting accounts requires super-auth access.'
                    else:
                        flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userDelete', user_id=userID))
                else:
                    errMsg = 'Action failed; unexpected action.'
            if errMsg is not None:
                flask.flash(errMsg)
                flaskResponse = flask.redirect(flask.url_for(f'{self.blueprint.name}.page_userViewAll'))
        else:
            authAccounts_users_records = self.dbModelContext.authaccounts_users_read()
            sudoer_user_ids = {
                record.id
                for record in authAccounts_users_records
                if self.dbModelContext.authaccounts_user_allowPrivilege_read(record.id, ('sudo',))
            }
            flaskResponse.data = flask.render_template(
                'auth/userViewAll.html',
                authAccounts_users_records=authAccounts_users_records,
                authsession_session_record=_auth_authsession_session_record,
                caller_is_super_auth=caller_is_super_auth,
                group_users_update_allow=group_users_update_allow,
                sudoer_user_ids=sudoer_user_ids,
                urlUserCreate=flask.url_for(f'{self.blueprint.name}.page_userCreate'),
            )
        return flaskResponse

    def _authsession_session_record_read(self) ->object:
        """
        Returns the `authsession_session_record` associated with the active
        Flask session, or `None` if no valid session record could be found.
        """
        try:
            ret = self.dbModelContext.authsession_session_readByCookieID(flask.session[self.session_keys_session_cookie_id_str])
            assert(ret.wolc_authaccounts__user__id == flask.session[self.session_keys_user_id_str])
        except (KeyError, ValueError):  #No valid session could be found.
            ret = None
        return ret
