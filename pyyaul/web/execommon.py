from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

from pyyaul.base import execommon as base_execommon


DEFAULT_FLASK_PROXY_FIX = {
    'x_for': 1,
    'x_proto': 1,
    'x_host': 1,
}


def _dict_merge(base :dict, extra :dict) -> dict:
    merged = deepcopy(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _dict_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def cfgDefaults_merge(*cfg_defaults :dict|None) -> dict:
    merged = {}
    for item in cfg_defaults:
        if item is None:
            continue
        merged = _dict_merge(merged, item)
    return merged


def cfgDefaults_flask_make(
        host ='0.0.0.0',
        port =80,
        debug =False,
        proxy_fix :dict|None =None,
) -> dict:
    return {
        'DB': {
            'SSL_MODE': 'require',
        },
        'FLASK': {
            'DEBUG': debug,
            'HOST': host,
            'PORT': port,
            'PROXY_FIX': deepcopy(
                DEFAULT_FLASK_PROXY_FIX if proxy_fix is None else proxy_fix
            ),
        },
    }


def cfgDefaults_postgresRoot_make(
        dbname ='',
        host ='127.0.0.1',
        port ='5432',
        username ='user',
        password ='password',
) -> dict:
    return {
        'DB_ROOT': {
            'DBNAME': dbname,
            'HOST': host,
            'PORT': port,
            'ROOT_PASS': password,
            'ROOT_USER': username,
        },
    }


def cfgDefaults_postgresRolePair_make(
        section_name :str,
        dbname :str,
        schemaname :str|None =None,
        host ='127.0.0.1',
        port ='5432',
        ro_user ='user',
        ro_pass ='password',
        rw_user ='user',
        rw_pass ='password',
) -> dict:
    if schemaname is None:
        schemaname = dbname
    return {
        section_name: {
            'DBNAME': dbname,
            'HOST': host,
            'PORT': port,
            'RO_PASS': ro_pass,
            'RO_USER': ro_user,
            'RW_PASS': rw_pass,
            'RW_USER': rw_user,
            'SCHEMANAME': schemaname,
        },
    }


def cfgDefaults_authPostgres_make(
        schema_prefix ='auth',
        db_root_name ='',
) -> dict:
    return cfgDefaults_merge(
        {
            'DB': {
                'SSL_MODE': 'require',
            },
        },
        cfgDefaults_postgresRoot_make(dbname=db_root_name),
        cfgDefaults_postgresRolePair_make(
            'DB_USERACCOUNTS',
            f'{schema_prefix}_useraccounts',
            schemaname=f'{schema_prefix}_useraccounts',
        ),
        cfgDefaults_postgresRolePair_make(
            'DB_USERSESSIONS',
            f'{schema_prefix}_usersessions',
            schemaname=f'{schema_prefix}_usersessions',
        ),
        cfgDefaults_postgresRolePair_make(
            'DB_ADMINACCOUNTS',
            f'{schema_prefix}_adminaccounts',
            schemaname=f'{schema_prefix}_adminaccounts',
        ),
        cfgDefaults_postgresRolePair_make(
            'DB_ADMINSESSIONS',
            f'{schema_prefix}_adminsessions',
            schemaname=f'{schema_prefix}_adminsessions',
        ),
    )


def _cfg_defaults_apply(cfg_file, cfg_defaults :dict, prefix :tuple[str, ...] =()):
    for key, value in cfg_defaults.items():
        path = prefix + (key,)
        if isinstance(value, dict):
            _cfg_defaults_apply(cfg_file, value, path)
            continue
        if cfg_file.get(path, reload=True) is None:
            cfg_file.set(path, deepcopy(value), save=True)


@dataclass
class Ctx:
    pathRootDir :Path
    cfgFilePath :Path
    cfgFile :object
    cfgDefaults :dict

    def cfgGet(self, component, keys, default=None, setDefaultIfMissing=True):
        if isinstance(keys, str):
            keys = (keys,)
        ret = self.cfgFile.get((component,) + keys, default, reload=True)
        if setDefaultIfMissing and ret == default:
            self.cfgSet(component, keys, default)
        return ret

    def cfgSet(self, component, keys, val):
        if isinstance(keys, str):
            keys = (keys,)
        self.cfgFile.set((component,) + keys, deepcopy(val), save=True)


CTX :Ctx|None =None


def init(
        pathRootDir,
        cfgDefaults :dict|None =None,
        cfgFilePath =None,
) -> Ctx:
    global CTX
    base_execommon.init()
    from pyyaul.base.file.json import JsonFile

    pathRootDir = Path(pathRootDir).resolve()
    cfgFilePath = (
        (pathRootDir / 'cfg.json').resolve() if cfgFilePath is None
        else Path(cfgFilePath).resolve()
    )
    resolved_defaults = cfgDefaults_merge(cfgDefaults)
    cfgFile = JsonFile(cfgFilePath)
    _cfg_defaults_apply(cfgFile, resolved_defaults)
    CTX = Ctx(pathRootDir, cfgFilePath, cfgFile, resolved_defaults)
    return CTX


def ctxGet() -> Ctx:
    if CTX is None:
        raise RuntimeError('ERROR: `pyyaul.web.execommon.init(...)` must be called first.')
    return CTX


def cfgGet(component, keys, default=None, setDefaultIfMissing=True):
    return ctxGet().cfgGet(component, keys, default, setDefaultIfMissing)


def cfgSet(component, keys, val):
    return ctxGet().cfgSet(component, keys, val)
