from unittest import TestCase
from unittest.mock import MagicMock


class Test_DBModelContext(TestCase):

    def setUp(self):
        from pyyaul.web.compliance.db.model import DBModelContext
        from pyyaul.web.compliance.db.schema.v0 import ComplianceSchemaV0_Base
        self.DBModelContext = DBModelContext
        self.schema = ComplianceSchemaV0_Base('wolc_compliance')

    def _make_ctx(self):
        session = MagicMock()
        session_cm = MagicMock()
        session_cm.__enter__.return_value = session
        session_cm.__exit__.return_value = None
        orm_ro = MagicMock()
        orm_rw = MagicMock()
        orm_ro.session.return_value = session_cm
        orm_rw.session.return_value = session_cm
        orm_ro.tables = {
            'wolc_compliance.table_compliance_review': self.schema.metadata.tables['wolc_compliance.table_compliance_review'],
            'wolc_compliance.table_action_item': self.schema.metadata.tables['wolc_compliance.table_action_item'],
            'wolc_compliance.table_compliance_finding': self.schema.metadata.tables['wolc_compliance.table_compliance_finding'],
            'wolc_compliance.table_action_item_update': self.schema.metadata.tables['wolc_compliance.table_action_item_update'],
        }
        orm_rw.tables = {
            'wolc_compliance.table_compliance_review': self.schema.metadata.tables['wolc_compliance.table_compliance_review'],
            'wolc_compliance.table_action_item': self.schema.metadata.tables['wolc_compliance.table_action_item'],
            'wolc_compliance.table_compliance_finding': self.schema.metadata.tables['wolc_compliance.table_compliance_finding'],
            'wolc_compliance.table_action_item_update': self.schema.metadata.tables['wolc_compliance.table_action_item_update'],
        }
        return self.DBModelContext(orm_ro, orm_rw, self.schema), session, orm_ro, orm_rw

    def test_db_update_updates_rw_engine(self):
        ctx, _session, _orm_ro, orm_rw = self._make_ctx()
        self.schema.update = MagicMock()

        ctx.db_update()

        self.schema.update.assert_called_once_with(orm_rw.engine)

    def test_db_check_update_available_reflects_schema_match(self):
        ctx, _session, orm_ro, _orm_rw = self._make_ctx()
        self.schema.matches = MagicMock(return_value=True)

        self.assertFalse(ctx.db_checkUpdateAvailable())
        self.schema.matches.assert_called_once_with(orm_ro.engine)

    def test_action_item_status_set_commits(self):
        ctx, session, _orm_ro, _orm_rw = self._make_ctx()
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=MagicMock(id=3)))

        ctx.action_item_status_set(3, 'resolved', resolver_user_id=9)

        self.assertTrue(session.execute.called)
        self.assertTrue(session.commit.called)
