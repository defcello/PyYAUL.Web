from unittest import TestCase

from pyyaul.web.compliance.db.schema.v0 import ComplianceSchemaV0_Base


class Test_ComplianceSchemaV0_Base(TestCase):

    def setUp(self):
        self.schema = ComplianceSchemaV0_Base('wolc_compliance')

    def test_defines_expected_tables(self):
        self.assertEqual(
            {
                'wolc_compliance.table_compliance_review',
                'wolc_compliance.table_compliance_finding',
                'wolc_compliance.table_action_item',
                'wolc_compliance.table_action_item_update',
            },
            set(self.schema.metadata.tables.keys()),
        )

    def test_review_table_contains_expected_columns(self):
        table_review = self.schema.metadata.tables['wolc_compliance.table_compliance_review']

        self.assertIn('title', table_review.columns)
        self.assertIn('review_date', table_review.columns)
        self.assertIn('topic', table_review.columns)
        self.assertIn('scope', table_review.columns)
        self.assertIn('status', table_review.columns)
        self.assertIn('completed', table_review.columns)

    def test_action_item_update_table_contains_expected_columns(self):
        table_action_item_update = self.schema.metadata.tables['wolc_compliance.table_action_item_update']

        self.assertIn('action_item_id', table_action_item_update.columns)
        self.assertIn('update_type', table_action_item_update.columns)
        self.assertIn('notes', table_action_item_update.columns)
        self.assertIn('creator_user_id', table_action_item_update.columns)
