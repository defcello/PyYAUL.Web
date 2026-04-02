"""
Unit tests for modules.auth.model (pure business logic layer).

All database and session interactions are replaced with MagicMock stubs so no
Flask app or database connection is required.
"""

from unittest import TestCase
from unittest.mock import MagicMock, call




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


class Test_authAccountsRecord_info_set(TestCase):

	def setUp(self):
		from pyyaul.web.auth import model
		self.m = model
		self.session = MagicMock()
		self.session.wolc_authaccounts__user__id = 10

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


class Test_authAccountsRecord_isSuperauth_set(TestCase):

	def setUp(self):
		from pyyaul.web.auth import model
		self.m = model
		self.session = MagicMock()
		self.session.wolc_authaccounts__user__id = 1

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
