from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from pyyaul.web import execommon


class Test_execommon(TestCase):

    def tearDown(self):
        execommon.CTX = None

    def test_cfgGet_requires_init(self):
        with self.assertRaisesRegex(RuntimeError, 'init'):
            execommon.cfgGet('FLASK', 'HOST')

    def test_init_populates_cfg_json_with_nested_defaults(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)

            ctx = execommon.init(root, execommon.cfgDefaults_merge(
                execommon.cfgDefaults_flask_make(port=82),
                execommon.cfgDefaults_authPostgres_make(schema_prefix='wolc'),
                {
                    'APP': {
                        'NAME': 'skilltrails',
                    },
                },
            ))

            self.assertEqual(root / 'cfg.json', ctx.cfgFilePath)
            self.assertEqual('0.0.0.0', ctx.cfgGet('FLASK', 'HOST'))
            self.assertEqual(82, ctx.cfgGet('FLASK', 'PORT'))
            self.assertEqual('require', ctx.cfgGet('DB', 'SSL_MODE'))
            self.assertEqual('wolc_usersessions', ctx.cfgGet('DB_USERSESSIONS', 'SCHEMANAME'))
            self.assertEqual('skilltrails', ctx.cfgGet('APP', 'NAME'))

    def test_cfgGet_without_persisting_default_does_not_write_value(self):
        with TemporaryDirectory() as tmpdir:
            ctx = execommon.init(Path(tmpdir))

            self.assertEqual(
                'fallback',
                ctx.cfgGet('CLAUDE', 'ADMIN_USER', 'fallback', setDefaultIfMissing=False),
            )
            self.assertIsNone(ctx.cfgFile.get(('CLAUDE', 'ADMIN_USER'), reload=True))

    def test_cfgSet_persists_nested_values(self):
        with TemporaryDirectory() as tmpdir:
            execommon.init(Path(tmpdir))

            execommon.cfgSet('CLAUDE', ('SUPERADMIN_USER',), 'root_user')

            self.assertEqual(
                'root_user',
                execommon.cfgGet('CLAUDE', 'SUPERADMIN_USER'),
            )
