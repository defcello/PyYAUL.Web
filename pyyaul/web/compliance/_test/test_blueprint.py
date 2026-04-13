from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock

import flask
from jinja2 import ChoiceLoader, DictLoader

from pyyaul.web.auth.blueprint import BlueprintContext as AuthBlueprintContext
from pyyaul.web.compliance.blueprint import BlueprintContext


def _csrf_token_seed(client, token='test-csrf-token'):
    with client.session_transaction() as session:
        session['csrf_token'] = token
    return token


class Test_ComplianceBlueprintContext(TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.secret_key = 'testing'
        self.app.jinja_loader = ChoiceLoader([
            DictLoader({'base.html': '{% block content %}{% endblock %}'}),
            self.app.jinja_loader,
        ])
        self.auth_db = MagicMock()
        self.auth_blueprintContext = AuthBlueprintContext('adminauth', __name__, self.auth_db)
        self.auth_blueprintContext._authsession_session_record_read = MagicMock(
            return_value=SimpleNamespace(
                wolc_authaccounts__user__id=7,
                wolc_authaccounts__user__username='root',
                wolc_authaccounts__user__name_display='Root',
                wolc_authsession__session__id=11,
            )
        )
        from pyyaul.web.compliance.db.schema.v0 import ComplianceSchemaV0_Base
        self.db = MagicMock()
        self.db.dbSchema = ComplianceSchemaV0_Base('wolc_compliance')
        self.db.reviews_read.return_value = []
        self.db.action_items_read.return_value = []
        self.blueprintContext = BlueprintContext(
            'compliance',
            __name__,
            self.db,
            self.auth_blueprintContext,
        )
        self.app.register_blueprint(self.auth_blueprintContext.blueprint)
        self.app.register_blueprint(self.blueprintContext.blueprint)
        self.client = self.app.test_client()
        self.csrf_token = _csrf_token_seed(self.client)

    def test_index_requires_read_privilege(self):
        self.auth_db.authaccounts_user_allowPrivilege_read.return_value = False

        response = self.client.get('/compliance/')

        self.assertEqual(403, response.status_code)

    def test_index_renders_when_read_allowed(self):
        self.auth_db.authaccounts_user_allowPrivilege_read.return_value = True

        response = self.client.get('/compliance/')

        self.assertEqual(200, response.status_code)
        self.assertIn('Compliance', response.get_data(as_text=True))

    def test_create_review_requires_write_privilege(self):
        self.auth_db.authaccounts_user_allowPrivilege_read.side_effect = [False]

        response = self.client.post('/compliance/reviews/create', data={
            'csrf_token': self.csrf_token,
            'title': 'Quarterly Audit',
            'review_date': '2026-04-12',
            'topic': 'security',
            'scope': 'Public admin surfaces.',
        })

        self.assertEqual(403, response.status_code)
