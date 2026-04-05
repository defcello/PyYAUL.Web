"""
Unit tests for modules.auth.model (pure business logic layer).

All database and session interactions are replaced with MagicMock stubs so no
Flask app or database connection is required.
"""

from unittest import TestCase
from unittest.mock import MagicMock, call
from types import SimpleNamespace




class Test_authAccountsRecord_password_set(TestCase):

	def setUp(self):
		from pyyaul.web.auth import model
		self.m = model
		self.ctx = MagicMock()

	def test_non_string_raises(self):
		with self.assertRaises(ValueError):
			self.m.authAccountsRecord_password_set(self.ctx, 1, 12345, 8)

	def test_too_short_raises(self):
		with self.assertRaises(ValueError):
			self.m.authAccountsRecord_password_set(self.ctx, 1, 'short', 8)

	def test_exact_min_length_succeeds(self):
		self.m.authAccountsRecord_password_set(self.ctx, 1, 'exactly8', 8)
		self.ctx.authaccounts__user__password_hash__set.assert_called_once()
		call_args = self.ctx.authaccounts__user__password_hash__set.call_args
		self.assertEqual(call_args[0][0], 1)  # user_id

	def test_stored_hash_is_not_plaintext(self):
		password = 'supersecure123'
		self.m.authAccountsRecord_password_set(self.ctx, 42, password, 8)
		call_args = self.ctx.authaccounts__user__password_hash__set.call_args
		stored_hash = call_args[0][1]
		self.assertNotEqual(stored_hash, password)
		self.assertIsInstance(stored_hash, str)


class Test_authAccountsRecord_delete(TestCase):

	def setUp(self):
		from pyyaul.web.auth import model
		self.m = model
		self.session = MagicMock()
		self.session.wolc_authaccounts__user__id = 99
		self.session.wolc_authsession__session__id = 11

	def test_no_sudo_raises(self):
		ctx = MagicMock()
		ctx.authaccounts_user_allowPrivilege_read.return_value = False
		with self.assertRaises(ValueError):
			self.m.authAccountsRecord_delete(ctx, self.session, target_user_id=7)

	def test_sudo_calls_delete(self):
		ctx = MagicMock()
		ctx.authaccounts_user_allowPrivilege_read.return_value = True
		self.m.authAccountsRecord_delete(ctx, self.session, target_user_id=7)
		ctx.authaccounts_user_delete.assert_called_once_with(7, 99)

	def test_privilege_check_passes_session_id(self):
		ctx = MagicMock()
		ctx.authaccounts_user_allowPrivilege_read.return_value = True
		self.m.authAccountsRecord_delete(ctx, self.session, target_user_id=7)
		ctx.authaccounts_user_allowPrivilege_read.assert_called_once_with(
			99, ('sudo',), session_id=11
		)


class Test_authAccountsRecord_info_set(TestCase):

	def setUp(self):
		from pyyaul.web.auth import model
		self.m = model
		self.session = MagicMock()
		self.session.wolc_authaccounts__user__id = 10
		self.session.wolc_authsession__session__id = 22

	def _call(self, ctx, target_user_id):
		self.m.authAccountsRecord_info_set(
			ctx, self.session, target_user_id,
			name='Alice', email='a@b.com', phone_sms='555-1234',
		)

	def test_non_sudo_other_user_raises(self):
		ctx = MagicMock()
		ctx.authaccounts_user_allowPrivilege_read.return_value = False
		with self.assertRaises(ValueError):
			self._call(ctx, target_user_id=99)

	def test_non_sudo_self_succeeds(self):
		ctx = MagicMock()
		ctx.authaccounts_user_allowPrivilege_read.return_value = False
		self._call(ctx, target_user_id=10)  # same as caller
		ctx.authaccounts_user_info_set.assert_called_once()

	def test_sudo_can_update_other_user(self):
		ctx = MagicMock()
		ctx.authaccounts_user_allowPrivilege_read.return_value = True
		self._call(ctx, target_user_id=99)
		ctx.authaccounts_user_info_set.assert_called_once()

	def test_privilege_check_passes_session_id(self):
		ctx = MagicMock()
		ctx.authaccounts_user_allowPrivilege_read.return_value = True
		self._call(ctx, target_user_id=99)
		ctx.authaccounts_user_allowPrivilege_read.assert_called_once_with(
			10, ('sudo',), session_id=22
		)


class Test_authAccountsRecord_isSuperauth_set(TestCase):

	def setUp(self):
		from pyyaul.web.auth import model
		self.m = model
		self.session = MagicMock()
		self.session.wolc_authaccounts__user__id = 1
		self.session.wolc_authsession__session__id = 33

	def test_no_sudo_raises(self):
		ctx = MagicMock()
		ctx.authaccounts_user_allowPrivilege_read.return_value = False
		with self.assertRaises(ValueError):
			self.m.authAccountsRecord_isSuperauth_set(ctx, self.session, 5, True)

	def test_grant_sudo_calls_group_add(self):
		ctx = MagicMock()
		ctx.authaccounts_user_allowPrivilege_read.return_value = True
		self.m.authAccountsRecord_isSuperauth_set(ctx, self.session, 5, True)
		ctx.authaccounts_sudoers_group_user_add.assert_called_once_with(5, 1)
		ctx.authaccounts_sudoers_group_user_remove.assert_not_called()

	def test_revoke_sudo_calls_group_remove(self):
		ctx = MagicMock()
		ctx.authaccounts_user_allowPrivilege_read.return_value = True
		self.m.authAccountsRecord_isSuperauth_set(ctx, self.session, 5, False)
		ctx.authaccounts_sudoers_group_user_remove.assert_called_once_with(5, 1)
		ctx.authaccounts_sudoers_group_user_add.assert_not_called()

	def test_privilege_check_passes_session_id(self):
		ctx = MagicMock()
		ctx.authaccounts_user_allowPrivilege_read.return_value = True
		self.m.authAccountsRecord_isSuperauth_set(ctx, self.session, 5, True)
		ctx.authaccounts_user_allowPrivilege_read.assert_called_once_with(
			1, ('sudo',), session_id=33
		)


class Test_DBModelContext_authaccounts_user_allowPrivilege_read(TestCase):

	def setUp(self):
		from pyyaul.web.auth.db.model import DBModelContext
		self.DBModelContext = DBModelContext

	def _make_ctx(self, execute_results):
		session = MagicMock()
		session.execute.side_effect = execute_results
		session_cm = MagicMock()
		session_cm.__enter__.return_value = session
		session_cm.__exit__.return_value = None
		orm = MagicMock()
		orm.session.return_value = session_cm
		schema = SimpleNamespace(accountsSchemaName='auth', sessionsSchemaName='sessions')
		ctx = self.DBModelContext(orm, orm, orm, orm, schema)
		ctx.authaccounts_privilege_read = MagicMock(return_value=7)
		ctx.authaccounts_privilege_log_write = MagicMock()
		return ctx, session

	def test_without_session_uses_cached_boolean_only(self):
		ctx, session = self._make_ctx([MagicMock(scalar_one=MagicMock(return_value=True))])

		allowed = ctx.authaccounts_user_allowPrivilege_read(42, ('sudo',))

		self.assertTrue(allowed)
		self.assertEqual(session.execute.call_count, 1)
		self.assertIn('function_user_has_privilege(', str(session.execute.call_args_list[0].args[0]))
		ctx.authaccounts_privilege_log_write.assert_not_called()

	def test_denied_with_session_logs_nil_rule_without_nocache_lookup(self):
		ctx, session = self._make_ctx([MagicMock(scalar_one=MagicMock(return_value=False))])

		allowed = ctx.authaccounts_user_allowPrivilege_read(42, ('sudo',), session_id=11)

		self.assertFalse(allowed)
		self.assertEqual(session.execute.call_count, 1)
		self.assertIn('function_user_has_privilege(', str(session.execute.call_args_list[0].args[0]))
		ctx.authaccounts_privilege_log_write.assert_called_once_with(11, 7, False, allow_rule_id=None, on_log_error=None)

	def test_allowed_with_session_fetches_rule_id_for_logging(self):
		ctx, session = self._make_ctx([
			MagicMock(scalar_one=MagicMock(return_value=True)),
			MagicMock(fetchone=MagicMock(return_value=SimpleNamespace(allowed=True, rule_id=99))),
		])

		allowed = ctx.authaccounts_user_allowPrivilege_read(42, ('sudo',), session_id=11)

		self.assertTrue(allowed)
		self.assertEqual(session.execute.call_count, 2)
		self.assertIn('function_user_has_privilege(', str(session.execute.call_args_list[0].args[0]))
		self.assertIn('function_user_has_privilege_nocache_with_rule(', str(session.execute.call_args_list[1].args[0]))
		ctx.authaccounts_privilege_log_write.assert_called_once_with(11, 7, True, allow_rule_id=99, on_log_error=None)

	def test_with_session_passes_log_error_callback(self):
		ctx, _session = self._make_ctx([MagicMock(scalar_one=MagicMock(return_value=False))])
		on_log_error = MagicMock()

		allowed = ctx.authaccounts_user_allowPrivilege_read(
			42, ('sudo',), session_id=11, on_log_error=on_log_error
		)

		self.assertFalse(allowed)
		ctx.authaccounts_privilege_log_write.assert_called_once_with(
			11, 7, False, allow_rule_id=None, on_log_error=on_log_error
		)

	def test_privilege_log_write_invokes_error_callback_and_suppresses(self):
		from pyyaul.web.auth.db.model import DBModelContext

		session = MagicMock()
		session.execute.side_effect = RuntimeError('log failed')
		session_cm = MagicMock()
		session_cm.__enter__.return_value = session
		session_cm.__exit__.return_value = None
		orm = MagicMock()
		orm.session.return_value = session_cm
		schema = SimpleNamespace(accountsSchemaName='auth', sessionsSchemaName='sessions')
		ctx = DBModelContext(orm, orm, orm, orm, schema)
		on_log_error = MagicMock()

		ctx.authaccounts_privilege_log_write(11, 7, True, allow_rule_id=99, on_log_error=on_log_error)

		on_log_error.assert_called_once()
		self.assertIsInstance(on_log_error.call_args.args[0], RuntimeError)


class Test_DBModelContext_authaccounts_user_login_ip_attempts_recent_count(TestCase):

	def setUp(self):
		from pyyaul.web.auth.db.model import DBModelContext
		self.DBModelContext = DBModelContext

	def _make_ctx(self, scalar_value):
		session = MagicMock()
		session.execute.return_value = MagicMock(scalar_one=MagicMock(return_value=scalar_value))
		session_cm = MagicMock()
		session_cm.__enter__.return_value = session
		session_cm.__exit__.return_value = None
		orm = MagicMock()
		orm.session.return_value = session_cm
		schema = SimpleNamespace(accountsSchemaName='auth', sessionsSchemaName='sessions')
		ctx = self.DBModelContext(orm, orm, orm, orm, schema)
		return ctx, session

	def test_filters_by_ip_window_and_loginmethod_when_provided(self):
		ctx, session = self._make_ctx(7)

		count = ctx.authaccounts_user_login_ip_attempts_recent_count('203.0.113.9', 300, loginmethod_id=5)

		self.assertEqual(7, count)
		sql = str(session.execute.call_args.args[0])
		params = session.execute.call_args.args[1]
		self.assertIn("loginmethod_details->>'ip'", sql)
		self.assertIn('make_interval(secs => :window_seconds)', sql)
		self.assertIn('loginmethod_id = :loginmethod_id', sql)
		self.assertEqual({'ip': '203.0.113.9', 'window_seconds': 300, 'loginmethod_id': 5}, params)

	def test_loginmethod_filter_is_optional(self):
		ctx, session = self._make_ctx(2)

		count = ctx.authaccounts_user_login_ip_attempts_recent_count('203.0.113.9', 60)

		self.assertEqual(2, count)
		sql = str(session.execute.call_args.args[0])
		params = session.execute.call_args.args[1]
		self.assertNotIn('loginmethod_id = :loginmethod_id', sql)
		self.assertEqual({'ip': '203.0.113.9', 'window_seconds': 60}, params)
