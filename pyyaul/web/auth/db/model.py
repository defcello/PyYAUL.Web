"""
Interface module for the database.
"""

import sqlalchemy
from .schema.vLatest import Schema
from collections import namedtuple
from datetime import datetime, timezone
from sqlalchemy.orm import Session
def __sqlalchemy_recordDetachFromSession(ormRecord, session :Session) ->object:
	"""
	Detaches `ormRecord` from `session`, including loading all lazy-loaded
	attributes.

	Returns `ormRecord` for convenience.
	"""
	mapper = sqlalchemy.inspection.inspect(ormRecord).mapper
	for column in mapper.columns:
		getattr(ormRecord, column.name)
	session.expunge(ormRecord)
	return ormRecord
from inspect import isclass
from pyyaul.db.orm import ORM
from sqlalchemy import and_, insert, inspect, or_, select, text, update
import json
import logging
import secrets
import traceback




#Return type used for session record reads.
Record_authsession_session = namedtuple('Record_authsession_session', [
    'wolc_authsession__session__id',
    'wolc_authsession__session__cookie_id',
    'wolc_authaccounts__user__id',
    'wolc_authaccounts__user__username',
    'wolc_authaccounts__user__name_display',
])

BIGINT_MAX = 9223372036854775807
BIGINT_MIN = -9223372036854775808

class DBModelContext:

    dbSchema :Schema
    dbORM_authAccounts_RO :ORM
    dbORM_authAccounts_RW :ORM
    dbORM_authSessions_RO :ORM
    dbORM_authSessions_RW :ORM
    dbORM_path_authAccounts_table_user_str :str

    def __init__(
            self,
            dbORM_authAccounts_RO,
            dbORM_authAccounts_RW,
            dbORM_authSessions_RO,
            dbORM_authSessions_RW,
            dbSchema :Schema
    ):
        if isclass(dbSchema):
            raise ValueError('ERROR `dBschema` should be an instance, not a class.')
        self.dbORM_authAccounts_RO = dbORM_authAccounts_RO
        self.dbORM_authAccounts_RW = dbORM_authAccounts_RW
        self.dbORM_authSessions_RO = dbORM_authSessions_RO
        self.dbORM_authSessions_RW = dbORM_authSessions_RW
        self.dbSchema = dbSchema

    def authaccounts_privilege_create(
            self,
            creator_user_id :int,
            name :str,
            parent_id :int,
    ) -> int:
        """
        Creates a new privilege using the given details and returns its ID.
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            table_privilege = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_privilege']
            newRecord_id = dbSession.execute(
                insert(table_privilege).returning(table_privilege.id),
                {
                    'creator_user_id': creator_user_id,
                    'name': name,
                    'parent_id': parent_id,
                },
            ).scalar_one()
            dbSession.commit()
        return int(newRecord_id)

    def authaccounts_privilege_delete(
            self,
            privilege_id :int,
            deleter_user_id :int|None,
    ) -> list[int]:
        """
        Soft-deletes the given privilege and every descendant privilege.
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            deleted_ids = dbSession.execute(
                text(f"""
                    WITH RECURSIVE subtree AS (
                        SELECT id
                            FROM {self.dbSchema.accountsSchemaName}.table_privilege
                            WHERE id = :privilege_id
                                AND deleted IS NULL
                        UNION ALL
                        SELECT child.id
                            FROM {self.dbSchema.accountsSchemaName}.table_privilege child
                            JOIN subtree parent
                                ON child.parent_id = parent.id
                            WHERE child.deleted IS NULL
                    )
                    UPDATE {self.dbSchema.accountsSchemaName}.table_privilege
                        SET
                            deleter_user_id = :deleter_user_id,
                            deleted = timezone('utc', now())
                        WHERE id IN (SELECT id FROM subtree)
                            AND deleted IS NULL
                        RETURNING id
                    ;
                """),
                {
                    'privilege_id': privilege_id,
                    'deleter_user_id': deleter_user_id,
                },
            ).scalars().all()
            if len(deleted_ids) == 0:
                raise ValueError(f'ERROR Given `privilege_id` did not match any active records: {privilege_id=}')
            dbSession.commit()
        return list(deleted_ids)

    def authaccounts_privilege_read(
            self,
            privilege_path :list[str]|str,
    ) ->int|None:
        """
        Returns the `id` for the privilege matching `privilege_path`.

        `privilege_path` may be a simple string e.g. "sudo", but it is more
        commonly an iterable of strings denoting a path from "sudo" to a
        sub-privilege e.g. `('sudo', 'sudoers', 'read')`.

        Returns `None` on error.
        """
        ret = None
        dbORM = self.dbORM_authAccounts_RO
        if isinstance(privilege_path, str):
            privilege_path = (privilege_path,)
        with dbORM.session() as dbSession:
            table_privilege = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_privilege']
            privilege_id :int|None =None
            for privilege_name in privilege_path:
                result = dbSession.execute(
                    select(table_privilege.id)
                    .where(and_(
                        table_privilege.name == privilege_name,
                        table_privilege.deleted.is_(None),
                        (
                            table_privilege.parent_id.is_(None)
                            if privilege_id is None
                            else table_privilege.parent_id == privilege_id
                        ),
                    ))
                ).scalar_one_or_none()
                if result is None:
                    privilege_id = None
                    break
                privilege_id = result
            ret = privilege_id
        return ret

    def authaccounts_privilege_readByID(self, privilege_id :int) ->dict[str, object]:
        """
        Returns the privilege record matching `privilege_id` as a `dict` with
        the following keys`:
            - `record` is the privilege ORM record.
            - `path` is an iterable of `table_privilege.name` values from root up to and including this privilege.
            - `children_id` is an iterable of the `table_privilege.id` values
                for child privileges.
        """
        ret = None
        privileges = self.authaccounts_privileges_read()
        try:
            ret = privileges[privilege_id]
        except KeyError:
            pass
        return ret

    def authaccounts_privilege_update(
            self,
            privilege_id :int,
            name :str,
    ) -> int:
        """
        Renames the privilege matching `privilege_id`.
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            table_privilege = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_privilege']
            result = dbSession.execute(
                update(table_privilege)
                .returning(table_privilege.id)
                .where(and_(
                    table_privilege.id == privilege_id,
                    table_privilege.deleted.is_(None),
                ))
                .values(name=name)
            ).scalars().all()
            if len(result) == 0:
                raise ValueError(f'ERROR Given `privilege_id` did not match any active records: {privilege_id=}')
            if len(result) > 1:
                raise ValueError(f'CRITICAL ERROR Unexpected number of privileges matched: {privilege_id=}; {len(result)=}')
            dbSession.commit()
        return int(result[0])

    def authaccounts_privileges_read(self) ->dict[int, dict[str, object]]:
        """
        Returns all privilege records as a `dict` mapping `table_privilege.id`
        to a `dict`:
            - `record` is the privilege ORM record.
            - `path` is an iterable of `table_privilege.name` values from root up to and including this privilege.
            - `children_id` is an iterable of the `table_privilege.id` values
                for child privileges.
        """
        ret = {}
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            table_privilege = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_privilege']
            records = dbSession.execute(
                select(table_privilege).where(
                    table_privilege.deleted.is_(None),
                )
            ).scalars().all()
        if records is None:
            raise ValueError('CRITICAL ERROR `records` was unexpectedly `None`.')
        for record in records:
            ret[record.id] = {
                'record': record,
                'path': [record.name],
                'children_id': set(),
                'depth': 0,
                'path_str': record.name,
            }
        for record_dict in ret.values():
            parent_id = record_dict['record'].parent_id
            if parent_id is not None and parent_id in ret:
                ret[parent_id]['children_id'].add(record_dict['record'].id)
        for record_dict in ret.values():
            fence_parent_id = record_dict['record'].parent_id
            while fence_parent_id is not None:
                fence_parent_record = ret[fence_parent_id]['record']
                record_dict['path'].insert(0, fence_parent_record.name)
                fence_parent_id = fence_parent_record.parent_id
            record_dict['depth'] = len(record_dict['path']) - 1
            record_dict['path_str'] = '/'.join(record_dict['path'])
        return ret

    def authaccounts_user_allowPrivilege_read(
            self,
            user_id :int,
            privilege_path :list[str]|str,
            session_id :int|None =None,
            on_log_error =None,
    ) ->bool:
        """
        Returns `True` if ``user_id` should be allowed `privilege_name` and
        `False` if they should be denied.

        `privilege_path` may be a simple string e.g. "sudo", but it is more
        commonly an iterable of strings denoting a path from "sudo" to a
        sub-privilege e.g. `('sudo', 'sudoers', 'read')`.

        If the exact privilege path does not exist, this falls back to the
        nearest existing ancestor so newly introduced child privileges can be
        bootstrapped by older parent grants.

        When `session_id` is provided, the result is written to
        `table_privilege_log` so that all access-control decisions are auditable.
        """
        ret = False
        privilege_path_parts = (privilege_path,) if isinstance(privilege_path, str) else tuple(privilege_path)
        privilege_id = None
        search_path_parts = privilege_path_parts
        while privilege_id is None and len(search_path_parts) > 0:
            privilege_id = self.authaccounts_privilege_read(search_path_parts)
            search_path_parts = search_path_parts[:-1]
        rule_id = None
        if privilege_id is not None:
            dbORM = self.dbORM_authAccounts_RO
            with dbORM.session() as dbSession:
                result = dbSession.execute(text(f"""
                    SELECT COALESCE(
                            {self.dbSchema.accountsSchemaName}.function_user_has_privilege(
                                :user_id
                                , :privilege_id
                            )
                            , FALSE
                        )
                    ;
                """), {
                    'user_id': user_id,
                    'privilege_id': privilege_id,
                }).scalar_one()
                ret = bool(result)
                # Keep the boolean decision on the MV-backed path when the cache is
                # clean. Only resolve the winning rule on allows so audit logging can
                # record an informative rule ID without forcing every deny through the
                # recursive nocache function.
                if ret and session_id is not None:
                    row = dbSession.execute(text(f"""
                        SELECT r.allowed, r.rule_id
                            FROM {self.dbSchema.accountsSchemaName}.function_user_has_privilege_nocache_with_rule(
                                :user_id
                                , :privilege_id
                            ) AS r
                        ;
                    """), {
                        'user_id': user_id,
                        'privilege_id': privilege_id,
                    }).fetchone()
                    if row is not None:
                        rule_id = row.rule_id
            if session_id is not None:
                self.authaccounts_privilege_log_write(
                    session_id,
                    privilege_id,
                    ret,
                    allow_rule_id=rule_id,
                    on_log_error=on_log_error,
                )
        return ret

    def authaccounts_privilege_log_write(
            self,
            session_id :int,
            privilege_id :int,
            allowed :bool,
            allow_rule_id :int|None =None,
            on_log_error =None,
    ) ->None:
        """
        Appends a row to `table_privilege_log` recording that `session_id`
        requested `privilege_id` and was granted or denied.

        `allow_rule_id` is the `table_privilege_group_allow.id` of the winning
        rule, or `None` when the deny was implicit (no matching rule existed).

        Errors are printed and suppressed so that a logging failure never
        blocks the request being audited.
        """
        try:
            dbORM = self.dbORM_authSessions_RW
            with dbORM.session() as dbSession:
                dbSession.execute(
                    text(f"""
                        INSERT INTO {self.dbSchema.sessionsSchemaName}.table_privilege_log
                            (session_id, privilege_id, privilege_user_allow_id, allowed)
                        VALUES (:session_id, :privilege_id, :allow_rule_id, :allowed)
                        ;
                    """),
                    {
                        'session_id': session_id,
                        'privilege_id': privilege_id,
                        'allow_rule_id': allow_rule_id,
                        'allowed': allowed,
                    },
                )
        except Exception as e:
            if on_log_error is not None:
                try:
                    on_log_error(e)
                except Exception:
                    logging.exception('privilege log error callback failed')
            logging.warning(
                'privilege log write failed: session_id=%s privilege_id=%s allowed=%s allow_rule_id=%s error=%s',
                session_id, privilege_id, allowed, allow_rule_id, e,
            )

    def authaccounts_user_create(
            self,
            username :str,
            name :str,
            email :str,
            phone_sms :str,
            creator_user_id :int|None,
    )->object:
        """
        Creates a new user account using the given details and returns the full
        ORM record.

        If `creator_user_id` is `None`, the new record will create itself so the
        row remains valid even when the caller originates from another auth DB.

        The caller is responsible for separately granting `sudo` privilege
        (via `authaccounts_sudoers_group_user_add`) and setting a password
        (via `authaccounts__user__password_hash__set`) after creation.
        """
        userRecord = None
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            if creator_user_id is None:
                dbSession.execute(text(f"""
                    SET CONSTRAINTS
                        {self.dbSchema.accountsSchemaName}.foreign_key_constraint__table_user__creator_must_be_user
                        DEFERRED
                    ;
                """))
                newRecord_id = dbSession.execute(
                    text(f"""
                        INSERT INTO {self.dbSchema.accountsSchemaName}.table_user (
                            creator_user_id,
                            username,
                            name_display,
                            email,
                            phone_sms,
                            is_group,
                            is_loginenabled,
                            is_disabled
                        )
                        VALUES (
                            -1,
                            :username,
                            :name_display,
                            :email,
                            :phone_sms,
                            FALSE,
                            TRUE,
                            FALSE
                        )
                        RETURNING id
                        ;
                    """),
                    {
                        'username': username,
                        'name_display': name,
                        'email': email,
                        'phone_sms': phone_sms,
                    },
                ).scalar_one()
                dbSession.execute(
                    update(table_user)
                    .where(table_user.id == newRecord_id)
                    .values(creator_user_id=newRecord_id)
                )
                newRecord = dbSession.execute(
                    select(table_user).where(table_user.id == newRecord_id)
                ).scalar_one()
                dbSession.commit()
                userRecord = _sqlalchemy_recordDetachFromSession(newRecord, dbSession)
            else:
                newRecords = dbSession.scalars(
                    insert(table_user).returning(table_user),
                    [
                        {
                            'username': username,
                            'name_display': name,
                            'email': email,
                            'phone_sms': phone_sms,
                            'creator_user_id': creator_user_id,
                            'is_group': False,
                            'is_loginenabled': True,
                            'is_disabled': False,
                        },
                    ]
                ).all()
                if len(newRecords) == 0:
                    raise ValueError(f'ERROR Failed to create user account record in the database.')
                elif len(newRecords) > 1:
                    raise Exception(f'ERROR Unexpectedly created multiple user account records in the database; aborting operation.')
                else:
                    dbSession.commit()
                    userRecord = _sqlalchemy_recordDetachFromSession(newRecords[0], dbSession)
        return userRecord

    def authaccounts_user_delete(
            self,
            user_id :int,
            deleter_user_id :int,
    )->object:
        """
        Deletes the user record matching `user_id`.
        """
        dbORM = self.dbORM_authAccounts_RW
        table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
        if deleter_user_id is not None and not isinstance(deleter_user_id, int):
            raise ValueError(
                f'ERROR Given `deleter_user_id` was an unexpected type: {type(deleter_user_id)=} != int'
            )
        with dbORM.session() as dbSession:
            result = dbSession.execute(
                update(table_user).returning(table_user.id)
                .where(table_user.id == user_id)
                .values(
                    deleter_user_id=deleter_user_id,
                    deleted=sqlalchemy.func.now(),
                )
            ).all()
            if len(result) == 0:
                raise ValueError(f'ERROR Given `user_id` did not match any records: {user_id=}')
            elif len(result) > 1:
                raise Exception(f'ERROR Given `user_id` unexpectedly matched multiple records: {user_id=}')
            else:
                dbSession.commit()

    # def authaccounts_user__is_super_auth__set(
            # self,
            # user_id :int,
            # is_super_auth :bool,
    # )->object:
        # """
        # Updates the user record matching `user_id` to have the given
        # `is_super_auth` status.
        # """
        # dbORM = self.dbORM_authAccounts_RW
        # table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
        # with dbORM.session() as dbSession:
            # result = dbSession.execute(
                # update(table_user).returning(table_user.id)
                # .where(table_user.id == user_id)
                # .values(is_super_auth=is_super_auth)
            # ).all()
            # if result.rowcount == 0:
                # raise ValueError(f'ERROR Given `user_id` did not match any records: {user_id=}')
            # elif result.rowcount > 1:
                # raise Exception(f'ERROR Given `user_id` unexpectedly matched multiple records: {user_id=}; {result.rowcount=}')
            # else:
                # dbSession.commit()

    def authaccounts_user_shadow_sync(
            self,
            user_id :int,
            username :str,
            name_display :str,
            is_loginenabled :bool,
    ) -> int:
        """
        Updates internal shadow-account fields used for cross-database admin actors.
        """
        dbORM = self.dbORM_authAccounts_RW
        table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
        with dbORM.session() as dbSession:
            result = dbSession.execute(
                update(table_user).returning(table_user.id)
                .where(and_(
                    table_user.id == user_id,
                    table_user.deleted.is_(None),
                ))
                .values(
                    username=username,
                    name_display=name_display,
                    is_loginenabled=is_loginenabled,
                    is_disabled=False,
                )
            ).scalars().all()
            if len(result) == 0:
                raise ValueError(f'ERROR Given `user_id` did not match any active records: {user_id=}')
            elif len(result) > 1:
                raise Exception(f'ERROR Given `user_id` unexpectedly matched multiple records: {user_id=}; {len(result)=}')
            else:
                dbSession.commit()
        return int(result[0])

    def authaccounts_user_info_set(
            self,
            user_id :int,
            user_name :str,
            user_email :str,
            user_phone_sms :str,
    )->object:
        """
        Updates the user record matching `user_id` to have the given info.
        """
        dbORM = self.dbORM_authAccounts_RW
        table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
        with dbORM.session() as dbSession:
            result = dbSession.execute(
                update(table_user).returning(table_user.id)
                .where(table_user.id == user_id)
                .values(name_display=user_name, email=user_email, phone_sms=user_phone_sms)
            ).all()
            if len(result) == 0:
                raise ValueError(f'ERROR Given `user_id` did not match any records: {user_id=}')
            elif len(result) > 1:
                raise Exception(f'ERROR Given `user_id` unexpectedly matched multiple records: {user_id=}')
            else:
                dbSession.commit()

    def authaccounts__user__password_hash__set(
            self,
            user_id :int,
            password_hash :str,
    )->None:
        """
        Upserts the password hash for the user matching `user_id` into
        `table_user_loginmethod_password`.

        Uses INSERT … ON CONFLICT so it handles both the initial password set
        (after `authaccounts_user_loginmethod_add`) and subsequent resets.
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            dbSession.execute(
                text(f"""
                    INSERT INTO {self.dbSchema.accountsSchemaName}.table_user_loginmethod_password
                            (creator_user_id, user_id, password_hash)
                        VALUES (:user_id, :user_id, :password_hash)
                        ON CONFLICT (user_id) WHERE deleted IS NULL
                        DO UPDATE SET password_hash = EXCLUDED.password_hash
                    ;
                """),
                {'user_id': user_id, 'password_hash': password_hash},
            )
            dbSession.commit()

    def authaccounts_user_passwordHash_readByID(self, userID :int) ->object|None:
        """
        Returns the password hash for the given `userID`'s login, or `None` if
        the user doesn't have password login as an option.
        """
        ret = None
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            table_loginmethod = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_loginmethod']
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            table_user_loginmethod = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user_loginmethod']
            table_user_loginmethod_password = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user_loginmethod_password']
            table_user_loginmethod_password_records = dbSession.execute(
                select(inspect(table_user_loginmethod_password).columns['password_hash'])
                .join(table_user, inspect(table_user).columns['id'] == inspect(table_user_loginmethod_password).columns['user_id'])
                .join(table_user_loginmethod, inspect(table_user_loginmethod).columns['user_id'] == inspect(table_user).columns['id'])
                .join(table_loginmethod, inspect(table_user_loginmethod).columns['loginmethod_id'] == inspect(table_loginmethod).columns['id'])
                .where(
                    and_(
                        inspect(table_loginmethod).columns['name'] == self.dbSchema.LoginMethod.Password.value,
                        inspect(table_user_loginmethod_password).columns['user_id'] == userID,
                        inspect(table_user).columns['deleted'].is_(None),
                        inspect(table_user_loginmethod).columns['user_id'] == userID,
                        inspect(table_user_loginmethod).columns['deleted'].is_(None),
                        inspect(table_loginmethod).columns['is_disabled'].is_(True),
                        inspect(table_user_loginmethod_password).columns['deleted'].is_(None),
                    )
                )
            ).all()
            if len(table_user_loginmethod_password_records) == 0:
                raise ValueError(
                    f'ERROR Password lookup failed; verify the account is not deleted and has the {self.dbSchema.LoginMethod.Password.value!r} login method available: {userID=}; {len(userRecords)=}'
                )
            elif len(table_user_loginmethod_password_records) == 1:
                ret = table_user_loginmethod_password_records[0].password_hash
            else:  #Too many matches!  This shouldn't happen!
                raise ValueError(
                    f'CRITICAL ERROR Unexpected number of password records found: {userID=}; {len(userRecords)=}'
                )
        if ret is None:
            raise ValueError('CRITICAL ERROR `ret` was unexpectedly `None`.')
        print(f'{type(ret)=}')
        return ret

    def authaccounts_user_readByID(self, userID :int, cols_str :list[str] =('id',)) ->object:
        """
        Returns the auth accounts record with columns `cols_str` matching the
        given `user_emailORusername`.

        `cols_str` should be column names available in
        `f'{self.dbSchema.accountsSchemaName}.table_user'`.

        If `user_emailORusername` matches multiple users, this will fall back to
        `authaccounts_user_readByUsername`.  If that still resolves to multiple
        accounts (should be impossible if the database is constrained properly),
        then `ValueError` is raised.

        Raises `ValueError` if a matching record could not be found.  Caller may
        assume the returned value is never `None`.

        Caller may assume the return will never be `None` (raises exception on
        error).
        """
        ret = None
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            cols = []
            for col_str in cols_str:
                cols.append(getattr(table_user, col_str))
            userRecords = dbSession.execute(
                select(*cols).where(
                    and_(
                        table_user.id == userID,
                        table_user.deleted.is_(None),
                    )
                )
            ).all()
            if len(userRecords) == 0:
                raise ValueError(
                    f'ERROR No active user records found: {userID=}; {len(userRecords)=}'
                )
            elif len(userRecords) == 1:
                ret = userRecords[0]
            else:  #Too many matches!  This shouldn't happen!
                raise ValueError(
                    f'CRITICAL ERROR Unexpected number of active user records found: {userID=}; {len(userRecords)=}'
                )
        if ret is None:
            raise ValueError('CRITICAL ERROR `ret` was unexpectedly `None`.')
        print(f'{type(ret)=}')
        return ret

    def authaccounts_user_readByEmailOrUsername(self, user_emailORusername :str, cols_str :list[str] =('id',)) ->object:
        """
        Returns the auth accounts record with columns `cols_str` matching the
        given `user_emailORusername`.

        `cols_str` should be column names available in
        `f'{self.dbSchema.accountsSchemaName}.table_user'`.

        If `user_emailORusername` matches multiple users, this will fall back to
        `authaccounts_user_readByUsername`.  If that still resolves to multiple
        accounts (should be impossible if the database is constrained properly),
        then `ValueError` is raised.

        Raises `ValueError` if a matching record could not be found.  Caller may
        assume the returned value is never `None`.

        Caller may assume the return will never be `None` (raises exception on
        error).
        """
        ret = None
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            cols = []
            for col_str in cols_str:
                cols.append(getattr(table_user, col_str))
            userRecords = dbSession.execute(
                select(*cols).where(
                    and_(
                        or_(
                            table_user.username == user_emailORusername,
                            table_user.email == user_emailORusername,
                        ),
                        table_user.deleted.is_(None),
                    )
                )
            ).all()
            if len(userRecords) == 0:
                raise ValueError(
                    f'ERROR No active user records found: {user_emailORusername=}; {len(userRecords)=}'
                )
            elif len(userRecords) == 1:
                ret = userRecords[0]
            else:  #Too many matches!  Multiple accounts are likely associated with the same e-mail; we must look at the username only.
                print(
                    f'WARNING Too many matches with "e-mail or username" lookup; falling back to username lookup: {user_emailORusername=}'
                )
                ret = authaccounts_user_readByUsername(user_emailORusername)
        if ret is None:
            raise ValueError('CRITICAL ERROR `ret` was unexpectedly `None`.')
        print(f'{type(ret)=}')
        return ret

    def authaccounts_user_readByUsername(self, user_username :str, cols_str :list[str] =('id',)) ->object:
        """
        Returns the auth accounts record with columns `cols_str` matching the
        given `user_username`.

        `cols_str` should be column names available in
        `f'{self.dbSchema.accountsSchemaName}.table_user'`.

        If `user_username` matches multiple users, this will fall back to
        `authaccounts_user_readByUsername`.  If that still resolves to multiple
        accounts (should be impossible if the database is constrained properly),
        then `ValueError` is raised.

        Raises `ValueError` if a matching record could not be found.  Caller may
        assume the returned value is never `None`.

        Caller may assume the return will never be `None` (raises exception on
        error).
        """
        ret = None
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            cols = []
            for col_str in cols_str:
                cols.append(getattr(table_user, col_str))
            userRecords = dbSession.execute(
                select(*cols).where(
                    and_(
                        table_user.username == user_username,
                        table_user.deleted.is_(None),
                    )
                )
            ).all()
            if len(userRecords) == 0:
                raise ValueError(
                    f'ERROR No active user records found: {user_username=}; {len(userRecords)=}'
                )
            elif len(userRecords) == 1:
                ret = userRecords[0]
            else:  #Too many matches!  Multiple accounts are likely associated with the same e-mail; we must look at the username only.
                print(
                    f'WARNING Too many matches with "e-mail or username" lookup; falling back to username lookup: {user_username=}'
                )
                ret = authaccounts_user_readByUsername(user_username)
        if ret is None:
            raise ValueError('CRITICAL ERROR `ret` was unexpectedly `None`.')
        print(f'{type(ret)=}')
        return ret

    def authaccounts_users_read(self):
        """
        Returns all user records.
        """
        userRecord = None
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            userRecords = dbSession.execute(
                select(table_user).where(
                    table_user.deleted.is_(None),
                )
            ).scalars().all()
        if userRecords is None:
            raise ValueError('CRITICAL ERROR `userRecords` was unexpectedly `None`.')
        return userRecords

    def authaccounts_groups_read(self):
        """
        Returns all group records (rows where is_group=True).
        """
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            groupRecords = dbSession.execute(
                select(table_user).where(
                    table_user.is_group.is_(True),
                    table_user.deleted.is_(None),
                )
            ).scalars().all()
        if groupRecords is None:
            raise ValueError('CRITICAL ERROR `groupRecords` was unexpectedly `None`.')
        return groupRecords

    def authaccounts_group_create(
            self,
            username :str,
            creator_user_id :int,
            name_display :str|None =None,
    ) ->object:
        """
        Creates a new group record and returns the ORM record.
        """
        if name_display is None or name_display.strip() == '':
            name_display = username
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            newRecords = dbSession.scalars(
                insert(table_user).returning(table_user),
                [
                    {
                        'username': username,
                        'name_display': name_display,
                        'email': '',
                        'phone_sms': '',
                        'creator_user_id': creator_user_id,
                        'is_group': True,
                        'is_loginenabled': False,
                        'is_disabled': False,
                    },
                ]
            ).all()
            if len(newRecords) == 0:
                raise ValueError('ERROR Failed to create group record in the database.')
            if len(newRecords) > 1:
                raise Exception('ERROR Unexpectedly created multiple group records in the database; aborting operation.')
            dbSession.commit()
            ret = _sqlalchemy_recordDetachFromSession(newRecords[0], dbSession)
        return ret

    def authaccounts_group_readByID(self, group_id :int, cols_str :list[str] =('id',)) ->object:
        """
        Returns the active group matching `group_id`.
        """
        ret = None
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            cols = [getattr(table_user, col_str) for col_str in cols_str]
            groupRecords = dbSession.execute(
                select(*cols).where(
                    and_(
                        table_user.id == group_id,
                        table_user.is_group.is_(True),
                        table_user.deleted.is_(None),
                    )
                )
            ).all()
            if len(groupRecords) == 0:
                raise ValueError(f'ERROR No active group records found: {group_id=}; {len(groupRecords)=}')
            if len(groupRecords) > 1:
                raise ValueError(f'CRITICAL ERROR Unexpected number of active group records found: {group_id=}; {len(groupRecords)=}')
            ret = groupRecords[0]
        if ret is None:
            raise ValueError('CRITICAL ERROR `ret` was unexpectedly `None`.')
        return ret

    def authaccounts_group_readByUsername(self, group_username :str, cols_str :list[str] =('id',)) ->object:
        """
        Returns the active group matching `group_username`.
        """
        ret = None
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            cols = [getattr(table_user, col_str) for col_str in cols_str]
            groupRecords = dbSession.execute(
                select(*cols).where(
                    and_(
                        table_user.username == group_username,
                        table_user.is_group.is_(True),
                        table_user.deleted.is_(None),
                    )
                )
            ).all()
            if len(groupRecords) == 0:
                raise ValueError(f'ERROR No active group records found: {group_username=}; {len(groupRecords)=}')
            if len(groupRecords) > 1:
                raise ValueError(f'CRITICAL ERROR Unexpected number of active group records found: {group_username=}; {len(groupRecords)=}')
            ret = groupRecords[0]
        if ret is None:
            raise ValueError('CRITICAL ERROR `ret` was unexpectedly `None`.')
        return ret

    def authaccounts_group_update(
            self,
            group_id :int,
            username :str,
            name_display :str|None =None,
    ) -> int:
        """
        Renames the group matching `group_id`.
        """
        if name_display is None or name_display.strip() == '':
            name_display = username
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            result = dbSession.execute(
                update(table_user)
                .returning(table_user.id)
                .where(and_(
                    table_user.id == group_id,
                    table_user.is_group.is_(True),
                    table_user.deleted.is_(None),
                ))
                .values(
                    username=username,
                    name_display=name_display,
                )
            ).scalars().all()
            if len(result) == 0:
                raise ValueError(f'ERROR Given `group_id` did not match any active group records: {group_id=}')
            if len(result) > 1:
                raise ValueError(f'CRITICAL ERROR Unexpected number of groups matched: {group_id=}; {len(result)=}')
            dbSession.commit()
        return int(result[0])

    def authaccounts_group_members_read(self, group_id :int) -> list[dict[str, object]]:
        """
        Returns the direct members of the given group.
        """
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            rows = dbSession.execute(
                text(f"""
                    SELECT
                        gu.id AS membership_id,
                        u.id AS user_id,
                        u.username AS username,
                        u.name_display AS name_display,
                        u.is_group AS is_group,
                        gu.created AS created
                    FROM {self.dbSchema.accountsSchemaName}.table_group_user gu
                    JOIN {self.dbSchema.accountsSchemaName}.table_user u
                        ON u.id = gu.user_id
                    WHERE gu.group_user_id = :group_id
                        AND gu.deleted IS NULL
                        AND u.deleted IS NULL
                    ORDER BY u.is_group DESC, u.username ASC
                """),
                {'group_id': group_id},
            ).mappings().all()
        return [dict(row) for row in rows]

    def authaccounts_user_group_memberships_read(self, user_id :int) -> list[dict[str, object]]:
        """
        Returns the direct groups containing the given user or group.
        """
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            rows = dbSession.execute(
                text(f"""
                    SELECT
                        gu.id AS membership_id,
                        g.id AS group_id,
                        g.username AS group_username,
                        g.name_display AS group_name_display,
                        gu.created AS created
                    FROM {self.dbSchema.accountsSchemaName}.table_group_user gu
                    JOIN {self.dbSchema.accountsSchemaName}.table_user g
                        ON g.id = gu.group_user_id
                    WHERE gu.user_id = :user_id
                        AND gu.deleted IS NULL
                        AND g.deleted IS NULL
                        AND g.is_group IS TRUE
                    ORDER BY g.username ASC
                """),
                {'user_id': user_id},
            ).mappings().all()
        return [dict(row) for row in rows]

    def authaccounts_group_membership_add(
            self,
            group_id :int,
            user_id :int,
            creator_user_id :int,
    ) -> int:
        """
        Adds the given user or group to the given group.
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            groupRecord = dbSession.execute(
                select(table_user.id, table_user.username)
                .where(and_(
                    table_user.id == group_id,
                    table_user.is_group.is_(True),
                    table_user.deleted.is_(None),
                ))
            ).one_or_none()
            if groupRecord is None:
                raise ValueError(f'ERROR Group not found: {group_id=}')
            userRecord = dbSession.execute(
                select(table_user.id, table_user.username, table_user.is_group)
                .where(and_(
                    table_user.id == user_id,
                    table_user.deleted.is_(None),
                ))
            ).one_or_none()
            if userRecord is None:
                raise ValueError(f'ERROR User/group not found: {user_id=}')
            if group_id == user_id:
                raise ValueError('ERROR A group may not be added to itself.')
            if userRecord.is_group:
                cycle_exists = dbSession.execute(
                    text(f"""
                        WITH RECURSIVE nested_groups(group_id, path) AS (
                            SELECT :member_group_id::int, ARRAY[:member_group_id::int]
                            UNION ALL
                            SELECT
                                gu.user_id,
                                nested_groups.path || gu.user_id
                            FROM nested_groups
                            JOIN {self.dbSchema.accountsSchemaName}.table_group_user gu
                                ON gu.group_user_id = nested_groups.group_id
                                AND gu.deleted IS NULL
                            JOIN {self.dbSchema.accountsSchemaName}.table_user u
                                ON u.id = gu.user_id
                                AND u.deleted IS NULL
                                AND u.is_group IS TRUE
                            WHERE NOT (gu.user_id = ANY(nested_groups.path))
                        )
                        SELECT 1
                        FROM nested_groups
                        WHERE group_id = :group_id
                        LIMIT 1
                    """),
                    {'member_group_id': user_id, 'group_id': group_id},
                ).scalar_one_or_none()
                if cycle_exists is not None:
                    raise ValueError('ERROR This membership would create a group cycle.')
            inserted_id = dbSession.execute(
                text(f"""
                    INSERT INTO {self.dbSchema.accountsSchemaName}.table_group_user (
                        creator_user_id,
                        group_user_id,
                        user_id,
                        group_is_group
                    )
                    VALUES (
                        :creator_user_id,
                        :group_id,
                        :user_id,
                        TRUE
                    )
                    ON CONFLICT (group_user_id, user_id) WHERE deleted IS NULL
                    DO NOTHING
                    RETURNING id
                """),
                {
                    'creator_user_id': creator_user_id,
                    'group_id': group_id,
                    'user_id': user_id,
                },
            ).scalar_one_or_none()
            if inserted_id is None:
                raise ValueError('ERROR The selected account is already a direct member of that group.')
            dbSession.commit()
        return int(inserted_id)

    def authaccounts_group_membership_remove(
            self,
            group_id :int,
            user_id :int,
            deleter_user_id :int,
    ) -> list[int]:
        """
        Soft-removes the direct membership for `user_id` from `group_id`.
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            deleted_ids = dbSession.execute(
                text(f"""
                    UPDATE {self.dbSchema.accountsSchemaName}.table_group_user
                        SET
                            deleter_user_id = :deleter_user_id,
                            deleted = timezone('utc', now())
                        WHERE group_user_id = :group_id
                            AND user_id = :user_id
                            AND deleted IS NULL
                        RETURNING id
                """),
                {
                    'deleter_user_id': deleter_user_id,
                    'group_id': group_id,
                    'user_id': user_id,
                },
            ).scalars().all()
            if len(deleted_ids) == 0:
                raise ValueError('ERROR No active group membership matched the requested removal.')
            dbSession.commit()
        return list(deleted_ids)

    def authaccounts_group_privilege_rules_read(self, group_id :int) -> list[dict[str, object]]:
        """
        Returns the explicit allow/deny rules assigned to the given group.
        """
        privileges = self.authaccounts_privileges_read()
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            rows = dbSession.execute(
                text(f"""
                    SELECT
                        pga.id AS rule_id,
                        pga.privilege_id AS privilege_id,
                        pga.allow AS allow,
                        pga.created AS created
                    FROM {self.dbSchema.accountsSchemaName}.table_privilege_group_allow pga
                    JOIN {self.dbSchema.accountsSchemaName}.table_privilege p
                        ON p.id = pga.privilege_id
                    WHERE pga.group_user_id = :group_id
                        AND pga.deleted IS NULL
                        AND p.deleted IS NULL
                    ORDER BY pga.created ASC
                """),
                {'group_id': group_id},
            ).mappings().all()
        ret = []
        for row in rows:
            item = dict(row)
            privilege_details = privileges.get(item['privilege_id'])
            item['privilege_path'] = tuple(privilege_details['path']) if privilege_details is not None else tuple()
            item['privilege_path_str'] = privilege_details['path_str'] if privilege_details is not None else str(item['privilege_id'])
            ret.append(item)
        return ret

    def authaccounts_group_privilege_rule_set(
            self,
            group_id :int,
            privilege_id :int,
            allow :bool,
            creator_user_id :int,
    ) -> int:
        """
        Creates or updates an explicit allow/deny rule for the given group.
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            table_privilege = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_privilege']
            table_privilege_group_allow = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_privilege_group_allow']
            group_exists = dbSession.execute(
                select(table_user.id).where(and_(
                    table_user.id == group_id,
                    table_user.is_group.is_(True),
                    table_user.deleted.is_(None),
                ))
            ).scalar_one_or_none()
            if group_exists is None:
                raise ValueError(f'ERROR Group not found: {group_id=}')
            privilege_exists = dbSession.execute(
                select(table_privilege.id).where(and_(
                    table_privilege.id == privilege_id,
                    table_privilege.deleted.is_(None),
                ))
            ).scalar_one_or_none()
            if privilege_exists is None:
                raise ValueError(f'ERROR Privilege not found: {privilege_id=}')
            result = dbSession.execute(
                update(table_privilege_group_allow)
                .returning(table_privilege_group_allow.id)
                .where(and_(
                    table_privilege_group_allow.group_user_id == group_id,
                    table_privilege_group_allow.privilege_id == privilege_id,
                    table_privilege_group_allow.deleted.is_(None),
                ))
                .values(allow=allow)
            ).scalars().all()
            if len(result) == 0:
                rule_id = dbSession.execute(
                    insert(table_privilege_group_allow).returning(table_privilege_group_allow.id),
                    {
                        'creator_user_id': creator_user_id,
                        'group_user_id': group_id,
                        'privilege_id': privilege_id,
                        'allow': allow,
                    },
                ).scalar_one()
            elif len(result) == 1:
                rule_id = result[0]
            else:
                raise ValueError(f'CRITICAL ERROR Unexpected number of privilege rules matched: {group_id=}; {privilege_id=}; {len(result)=}')
            dbSession.commit()
        return int(rule_id)

    def authaccounts_group_privilege_rule_delete(
            self,
            group_id :int,
            privilege_id :int,
            deleter_user_id :int,
    ) -> list[int]:
        """
        Deletes the explicit allow/deny rule for the given group and privilege.
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            deleted_ids = dbSession.execute(
                text(f"""
                    UPDATE {self.dbSchema.accountsSchemaName}.table_privilege_group_allow
                        SET
                            deleter_user_id = :deleter_user_id,
                            deleted = timezone('utc', now())
                        WHERE group_user_id = :group_id
                            AND privilege_id = :privilege_id
                            AND deleted IS NULL
                        RETURNING id
                """),
                {
                    'deleter_user_id': deleter_user_id,
                    'group_id': group_id,
                    'privilege_id': privilege_id,
                },
            ).scalars().all()
            if len(deleted_ids) == 0:
                raise ValueError('ERROR No active privilege rule matched the requested removal.')
            dbSession.commit()
        return list(deleted_ids)

    def authaccounts_user_loginmethod_add(
            self,
            user_id :int,
            creator_user_id :int,
    ) ->None:
        """
        Links `user_id` to the "Username and Password" login method so the user
        can authenticate with a password.  Call this once when creating a new
        user account.

        If the login method record does not exist yet in this auth database,
        it will be created first using `creator_user_id` as the actor.
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            loginmethod_id = dbSession.execute(
                text(f"""
                    SELECT id
                        FROM {self.dbSchema.accountsSchemaName}.table_loginmethod
                        WHERE name = :loginmethod_name
                            AND deleted IS NULL
                        ORDER BY id ASC
                        LIMIT 1
                    ;
                """),
                {
                    'loginmethod_name': self.dbSchema.LoginMethod.Password.value,
                },
            ).scalar_one_or_none()
            if loginmethod_id is None:
                loginmethod_id = dbSession.execute(
                    text(f"""
                        INSERT INTO {self.dbSchema.accountsSchemaName}.table_loginmethod
                                (creator_user_id, name)
                            VALUES (
                                :creator_user_id,
                                :loginmethod_name
                            )
                            RETURNING id
                        ;
                    """),
                    {
                        'creator_user_id': creator_user_id,
                        'loginmethod_name': self.dbSchema.LoginMethod.Password.value,
                    },
                ).scalar_one()
            dbSession.execute(
                text(f"""
                    INSERT INTO {self.dbSchema.accountsSchemaName}.table_user_loginmethod
                            (creator_user_id, user_id, loginmethod_id)
                        VALUES (
                            :creator_user_id,
                            :user_id,
                            :loginmethod_id
                        )
                        ON CONFLICT (user_id, loginmethod_id) WHERE deleted IS NULL
                        DO NOTHING
                    ;
                """),
                {
                    'creator_user_id': creator_user_id,
                    'user_id': user_id,
                    'loginmethod_id': loginmethod_id,
                },
            )
            dbSession.commit()

    def authaccounts_sudoers_group_user_add(
            self,
            user_id :int,
            creator_user_id :int,
    ) ->None:
        """
        Adds `user_id` to the `sudoers` group, granting them the `sudo` privilege.

        No-op if the user is already a member (idempotent via ON CONFLICT DO NOTHING).
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            dbSession.execute(
                text(f"""
                    INSERT INTO {self.dbSchema.accountsSchemaName}.table_group_user
                            (creator_user_id, group_user_id, user_id, group_is_group)
                        SELECT
                            :creator_user_id
                            , sudoers.id
                            , :user_id
                            , TRUE
                            FROM {self.dbSchema.accountsSchemaName}.table_user AS sudoers
                            WHERE sudoers.username = 'sudoers'
                            AND sudoers.is_group = TRUE
                            AND sudoers.deleted IS NULL
                        ON CONFLICT (group_user_id, user_id) WHERE deleted IS NULL
                        DO NOTHING
                    ;
                """),
                {'creator_user_id': creator_user_id, 'user_id': user_id},
            )
            dbSession.commit()

    def authaccounts_sudoers_group_user_remove(
            self,
            user_id :int,
            deleter_user_id :int,
    ) ->None:
        """
        Soft-removes `user_id` from the `sudoers` group, revoking the `sudo`
        privilege.
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            dbSession.execute(
                text(f"""
                    UPDATE {self.dbSchema.accountsSchemaName}.table_group_user
                        SET
                            deleter_user_id = :deleter_user_id
                            , deleted = timezone('utc', now())
                        WHERE user_id = :user_id
                        AND group_user_id = (
                            SELECT id
                                FROM {self.dbSchema.accountsSchemaName}.table_user
                                WHERE username = 'sudoers'
                                AND is_group = TRUE
                                AND deleted IS NULL
                        )
                        AND deleted IS NULL
                    ;
                """),
                {'deleter_user_id': deleter_user_id, 'user_id': user_id},
            )
            dbSession.commit()

    def authaccounts_view_privilege_group_allow_cache__refresh(self) ->bool:
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            self.dbSchema.view_privilege_group_allow_cache__refresh(dbSession)

    def authsession_session_create(self, user_id :int) ->Record_authsession_session:
        """
        Creates and returns a new or existing session record, or `None` if the
        session could not be created.
        """
        ret = None
        retryMax = 10
        session__cookie_id = None
        success = False
        try:
            record_authsession_session = self.authsession_session_readByUserID(user_id)
        except ValueError:
            dbORM = self.dbORM_authSessions_RW
            with dbORM.session() as dbSession:
                table_session = dbORM.tables[f'{self.dbSchema.sessionsSchemaName}.table_session']
                while not success and retryMax > 0:
                    session__cookie_id = secrets.randbelow(BIGINT_MAX - BIGINT_MIN + 1) + BIGINT_MIN
                    try:
                        dbSession.add(table_session(cookie_id=session__cookie_id, user_id=user_id))
                    except:  #Typically a collision on the `cookie_id`; try another one.
                        traceback.print_exc()
                        print('ERROR while inserting new session record.')
                        session__cookie_id = None
                        retryMax -= 1
                        if retryMax <= 0:
                            print('CRITICAL ERROR Out of retries for creating a new session.')
                            break
                    else:
                        dbSession.commit()
                        success = True
        else:
            session__cookie_id = record_authsession_session.wolc_authsession__session__cookie_id
            success = True
        if success:
            ret = self.authsession_session_readByCookieID(session__cookie_id)
        return ret

    def authsession_session_deleteByID(self, session_id :int)->None:
        """
        Deletes the session record matching `id`.

        Note that this does not actually delete the record, but marks it as
        `deleted`.

        Raises `ValueError` if a matching record could not be found, or if too many
        records were found (should never happen).
        """
        dbORM = self.dbORM_authSessions_RW
        with dbORM.session() as dbSession:
            table_session = dbORM.tables[f'{self.dbSchema.sessionsSchemaName}.table_session']
            result = dbSession.execute(
                update(table_session).returning(table_session.id)
                .where(and_(
                    table_session.id == session_id,
                    table_session.deleted.is_(None),
                ))
                .values(deleted=sqlalchemy.func.now())
            ).all()
            len_result = len(result)
            if len_result == 0:
                print(
                    f'WARNING Given session ID did not match any active session records (likely already deactivated): {session_id=}; {len_result=}'
                )
            elif len_result == 1:
                print(
                    f'Session has been successfully closed: {session_id=}; {len_result=}'
                )
                dbSession.commit()
            else:  #Too many matches!  This shouldn't happen!
                raise ValueError(
                    f'CRITICAL ERROR Unexpected number of active sessions found: {session_id=}; {len_result=}'
                )

    def authsession_session_readByCookieID(self, session__cookie_id :int) ->Record_authsession_session:
        """
        Loads the session record matching `session__cookie_id`, ignoring deleted or
        expired sessions.

        Raises `ValueError` if a matching record could not be found.

        Caller may assume the returned value is never `None`.
        """
        ret = None
        dbORM = self.dbORM_authSessions_RO
        with dbORM.session() as dbSession:
            table_session = dbORM.tables[f'{self.dbSchema.sessionsSchemaName}.table_session']
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            sessions = dbSession.execute(
                select(
                    table_session.id.label('session_id'),
                    table_session.cookie_id.label('session__cookie_id'),
                    table_user.id.label('user_id'),
                    table_user.username.label('user_username'),
                    table_user.name_display.label('user_name_display'),
                )
                .join(table_user)
                .where(and_(
                    # table_session.cookie_id == session__cookie_id,
                    table_session.deleted.is_(None),
                    table_session.expires > datetime.now(timezone.utc),
                    table_user.deleted.is_(None),
                    table_user.is_disabled == False,
                    or_(
                        table_user.unlocked.is_(None),
                        table_user.unlocked <= datetime.now(timezone.utc),
                    ),
                ))
            ).all()
            if len(sessions) == 0:
                raise ValueError(
                    f'ERROR Given cookie ID did not match any active session records: {session__cookie_id=}; {len(sessions)=}'
                )
            elif len(sessions) == 1:
                ret = Record_authsession_session(*sessions[0])
            else:  #Too many matches!  This shouldn't happen!
                raise ValueError(
                    f'CRITICAL ERROR Unexpected number of active sessions found: {session__cookie_id=}; {len(sessions)=}'
                )
        if ret is None:
            raise ValueError('CRITICAL ERROR `ret` was unexpectedly `None`.')
        return ret

    def authsession_session_readByID(self, session_id :int)->Record_authsession_session:
        """
        Loads the session record matching `id`, ignoring deleted or
        expired sessions.

        Raises `ValueError` if a matching record could not be found.  Caller may
        assume the returned value is never `None`.

        Caller may assume the return will never be `None`.
        """
        ret = None
        dbORM = self.dbORM_authSessions_RO
        with dbORM.session() as dbSession:
            table_session = dbORM.tables[f'{self.dbSchema.sessionsSchemaName}.table_session']
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            sessions = dbSession.execute(
                select(
                    table_session.id.label('session_id'),
                    table_session.cookie_id.label('session__cookie_id'),
                    table_user.id.label('user_id'),
                    table_user.username.label('user_username'),
                    table_user.name_display.label('user_name_display'),
                )
                .join(table_user)
                .where(and_(
                    table_session.id == session_id,
                    table_session.deleted.is_(None),
                    table_session.expires > datetime.now(timezone.utc),
                ))
            ).all()
            if len(sessions) == 0:
                raise ValueError(
                    f'ERROR Given cookie ID did not match any active session records: {session_id=}; {len(sessions)=}'
                )
            elif len(sessions) == 1:
                ret = Record_authsession_session(*sessions[0])
            else:  #Too many matches!  This shouldn't happen!
                raise ValueError(
                    f'CRITICAL ERROR Unexpected number of active sessions found: {session_id=}; {len(sessions)=}'
                )
        if ret is None:
            raise ValueError('CRITICAL ERROR `ret` was unexpectedly `None`.')
        return ret

    def authsession_session_readByUserID(self, userID)->Record_authsession_session:
        """
        Loads an active session record matching `userID`, ignoring deleted or
        expired sessions.

        Raises `ValueError` if a matching record could not be found.  Caller may
        assume the returned value is never `None`.

        Caller may assume the return will never be `None`.
        """
        ret = None
        dbORM = self.dbORM_authSessions_RO
        with dbORM.session() as dbSession:
            table_session = dbORM.tables[f'{self.dbSchema.sessionsSchemaName}.table_session']
            table_user = dbORM.tables[f'{self.dbSchema.accountsSchemaName}.table_user']
            authSessionRecords = dbSession.execute(
                select(
                    table_session.id.label('session_id'),
                    table_session.cookie_id.label('session__cookie_id'),
                    table_user.id.label('user_id'),
                    table_user.username.label('user_username'),
                    table_user.name_display.label('user_name_display'),
                )
                .join(table_user)
                .where(and_(
                    table_session.user_id == userID,
                    table_session.deleted.is_(None),
                    table_session.expires > datetime.now(timezone.utc),
                ))
            ).all()
            if len(authSessionRecords) == 0:
                raise ValueError(
                    f'ERROR Given user ID did not match any active session records: {userID=}; {len(authSessionRecords)=}'
                )
            elif len(authSessionRecords) == 1:
                ret = Record_authsession_session(*authSessionRecords[0])
            else:  #Too many matches!  This shouldn't happen!
                raise ValueError(
                    f'CRITICAL ERROR Unexpected number of active sessions found: {userID=}; {len(authSessionRecords)=}'
                )
        if ret is None:
            raise ValueError('CRITICAL ERROR `ret` was unexpectedly `None`.')
        return ret

    def authaccounts_loginmethod_id_readByName(self, name :str) ->int:
        """
        Returns the `id` of the login method with the given `name`.

        Raises `ValueError` if not found.
        """
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            result = dbSession.execute(
                text(f"""
                    SELECT id
                        FROM {self.dbSchema.accountsSchemaName}.table_loginmethod
                        WHERE name = :name
                            AND deleted IS NULL
                        ORDER BY id ASC
                        LIMIT 1
                    ;
                """),
                {'name': name},
            ).scalar_one_or_none()
        if result is None:
            raise ValueError(f'ERROR Login method {name!r} not found.')
        return result

    def authaccounts_user_login_log(
            self,
            loginmethod_id :int,
            is_success :bool,
            user_id :int|None =None,
            session_id :int|None =None,
            unlocked =None,
            loginmethod_details :dict|None =None,
    ) ->int:
        """
        Inserts a login attempt record into `table_user_login` and returns its `id`.

        `unlocked` should be a timezone-aware `datetime` (UTC) if this attempt triggered
        an account lockout, otherwise `None`.

        `loginmethod_details` is an optional dict of contextual data (e.g. IP address,
        user agent) stored as JSON for forensic analysis.
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            row_id = dbSession.execute(
                text(f"""
                    INSERT INTO {self.dbSchema.accountsSchemaName}.table_user_login
                            (user_id, loginmethod_id, is_success, session_id, unlocked, loginmethod_details)
                        VALUES (
                            :user_id
                            , :loginmethod_id
                            , :is_success
                            , :session_id
                            , :unlocked
                            , :loginmethod_details
                        )
                        RETURNING id
                    ;
                """),
                {
                    'user_id': user_id,
                    'loginmethod_id': loginmethod_id,
                    'is_success': is_success,
                    'session_id': session_id,
                    'unlocked': unlocked,
                    'loginmethod_details': json.dumps(loginmethod_details) if loginmethod_details is not None else None,
                },
            ).scalar_one()
            dbSession.commit()
        return row_id

    def authaccounts_user_login_consecutive_failures_count(self, user_id :int) ->int:
        """
        Returns the number of consecutive failed login attempts for `user_id` since the
        most recent success (or since all time if there has never been a success).

        Looks at the 50 most recent attempts so this is bounded and fast.
        """
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            rows = dbSession.execute(
                text(f"""
                    SELECT is_success
                        FROM {self.dbSchema.accountsSchemaName}.table_user_login
                        WHERE user_id = :user_id
                        ORDER BY created DESC
                        LIMIT 50
                    ;
                """),
                {'user_id': user_id},
            ).all()
        count = 0
        for row in rows:
            if row.is_success:
                break
            count += 1
        return count

    def authaccounts_user_login_lockout_count(self, user_id :int) ->int:
        """
        Returns the total number of times `user_id` has been locked out
        (i.e., rows in `table_user_login` with `unlocked IS NOT NULL`).

        Used to select an escalating lockout duration.
        """
        dbORM = self.dbORM_authAccounts_RO
        with dbORM.session() as dbSession:
            result = dbSession.execute(
                text(f"""
                    SELECT COUNT(*)
                        FROM {self.dbSchema.accountsSchemaName}.table_user_login
                        WHERE user_id = :user_id
                            AND unlocked IS NOT NULL
                    ;
                """),
                {'user_id': user_id},
            ).scalar_one()
        return int(result)

    def authaccounts_user_unlocked_set(self, user_id :int, unlocked) ->None:
        """
        Sets `table_user.unlocked` for `user_id`.

        Pass a timezone-aware `datetime` (UTC) to lock the account until that time,
        or `None` to clear the lock.
        """
        dbORM = self.dbORM_authAccounts_RW
        with dbORM.session() as dbSession:
            dbSession.execute(
                text(f"""
                    UPDATE {self.dbSchema.accountsSchemaName}.table_user
                        SET unlocked = :unlocked
                        WHERE id = :user_id
                    ;
                """),
                {'user_id': user_id, 'unlocked': unlocked},
            )
            dbSession.commit()

    def db_checkUpdateAvailable(self) ->bool:
        """
        Returns `True` if a newer schema is available for the database.
        """
        return not (
            self.dbSchema.matches(self.dbORM_authAccounts_RO.engine)
            and self.dbSchema.matches(self.dbORM_authSessions_RO.engine)
        )
