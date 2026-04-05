#! /usr/bin/env python3.12

"""
Initial version of the database schema for this module.
"""

from enum import Enum
from pyyaul.db.version import Version
from sqlalchemy import and_, BigInteger, Boolean, CheckConstraint, Column, DateTime, DDL, event, ForeignKey, ForeignKeyConstraint, Index, Integer, JSON, String, text, UniqueConstraint
from sqlalchemy.engine import Connection
from sqlalchemy.engine.base import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.schema import Table
from textwrap import dedent as d
import bcrypt
import random
import sqlalchemy
import string




class SchemaV0_Base(Version):

    clsPrev = None
    accountsSchemaName :str|None =None
    sessionsSchemaName :str|None =None

    class LoginMethod(Enum):
        Password = 'Username and Password'
        Passkey = 'Passkey'

    def __init__(self, accountsSchemaName, sessionsSchemaName, *args, **kargs):
        self.accountsSchemaName = accountsSchemaName
        self.sessionsSchemaName = sessionsSchemaName
        super().__init__(*args, **kargs)

    def _initialize(self, engine :Engine) ->Engine:
        if None not in (self.accountsSchemaName, self.sessionsSchemaName):
            with engine.connect() as connection:
                with connection.begin() as transaction:
                    self.schema_create(connection, self.accountsSchemaName, True)
                    self.schema_create(connection, self.sessionsSchemaName, True)
                    transaction.commit()
        return super()._initialize(engine)

    def _initMetaData(self, metadata):
        if None in (self.accountsSchemaName, self.sessionsSchemaName):
            return  #No schema to initialize in.
        #### `table_user` ##########################################################################
        #Expresses all the registered users and their authentication details.
        table_user = Table(
            'table_user',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('creator_user_id', Integer, nullable=False),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc'::text, now())")),
            Column('deleter_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id')),
            Column('deleted', DateTime(timezone=True)),
            Column('username', String(50), nullable=False),
            Column('name_display', String(100)),  #The name to display to the user as their name.
            Column('email', String(255), nullable=True),
            Column('phone_sms', String(15)),
            Column('is_group', Boolean, nullable=False),  #Set to `TRUE` for user groups; `FALSE` for normal .
            Column('is_loginenabled', Boolean, nullable=False),  #Set to `FALSE` for user groups and automation accounts.
            Column('is_disabled', Boolean, nullable=False),  #Set to `TRUE` if the account has been disabled (cannot login, has no privileges).
            Column('unlocked', DateTime(timezone=True), nullable=True, server_default=None),  #Set to the date/time that the user's account becomes unlocked; NULL means they've never been locked.
            Column('webauthn_user_id', sqlalchemy.LargeBinary, nullable=True),  #Opaque user handle for WebAuthn / passkeys.
            ForeignKeyConstraint(
                ['creator_user_id'],
                [f'{self.accountsSchemaName}.table_user.id'],
                name='foreign_key_constraint__table_user__creator_must_be_user',
                deferrable=True,
                initially='IMMEDIATE',
            ),
            UniqueConstraint('id', 'is_group', name='constraint_unique__table_user__id__is_group'),  #Used to enforce `table_group_user.group_user_id` is always a group.
            schema=self.accountsSchemaName,
        )
        Index(
            'unique_email_username_if_not_deleted',
            table_user.c.email,
            table_user.c.username,
            postgresql_where=table_user.c.deleted.is_(None),
            unique=True,
        )
        Index(  #Performance index for group lookups.
            'index__table_user__group_only',
            table_user.c.id,
            table_user.c.is_group,
            postgresql_where=and_(
                table_user.c.deleted.is_(None)
                , table_user.c.is_group.is_(True)
            ),
            unique=True,
        )
        Index(
            'unique_webauthn_user_id_if_not_deleted',
            table_user.c.webauthn_user_id,
            postgresql_where=and_(
                table_user.c.deleted.is_(None),
                table_user.c.webauthn_user_id.is_not(None),
            ),
            unique=True,
        )
        #### `view_group` ##########################################################################
        #Expresses all the registered groups.
        create_view = DDL(d(f"""
            CREATE OR REPLACE VIEW {self.accountsSchemaName}.view_group
                AS SELECT *
                    FROM {self.accountsSchemaName}.table_user
                    WHERE deleted IS NULL
                        AND is_group = TRUE
            ;
        """))
        drop_view = DDL(d(f"""
            DROP VIEW IF EXISTS {self.accountsSchemaName}.view_group
            ;
        """))
        event.listen(
            metadata,
            'after_create',
            create_view
        )
        event.listen(
            metadata,
            'before_drop',
            drop_view
        )
        #### `table_loginmethod` ##########################################################################
        #Expresses available user login methods.
        table_loginmethod = Table(
            'table_loginmethod',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('creator_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc'::text, now())")),
            Column('deleter_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id')),
            Column('deleted', DateTime(timezone=True)),
            Column('name', String(100), nullable=False),
            Column('is_disabled', Boolean, nullable=False, server_default=text("true")),  #Set to `TRUE` if the login method is currently unavailable.
            schema=self.accountsSchemaName,
        )
        Index(
            'unique_email_if_enabled_and_not_deleted',
            table_loginmethod.c.name,
            postgresql_where=and_(
                table_loginmethod.c.is_disabled.is_(False)
                , table_loginmethod.c.deleted.is_(None)
            ),
            unique=True,
        )
        #### `table_user_loginmethod` ####################################################################
        #Expresses all assignments of login methods available to specific users.
        #For example:
        #    - "Username/Password"
        #    - "API Key"
        table_user_loginmethod = Table(
            'table_user_loginmethod',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('creator_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc'::text, now())")),
            Column('deleter_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id')),
            Column('deleted', DateTime(timezone=True)),
            Column('user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('loginmethod_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_loginmethod.id'), nullable=False),
            schema=self.accountsSchemaName,
        )
        Index(
            'unique_user_loginmethod_if_not_deleted',
            table_user_loginmethod.c.user_id,
            table_user_loginmethod.c.loginmethod_id,
            postgresql_where=table_user_loginmethod.c.deleted.is_(None),
            unique=True,
        )
        #### `table_user_loginmethod_password` ####################################################################
        #Expresses the user-specific details for the "Username/Password" login method.
        table_user_loginmethod_password = Table(
            'table_user_loginmethod_password',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('creator_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc'::text, now())")),
            Column('deleter_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id')),
            Column('deleted', DateTime(timezone=True)),
            Column('user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('password_hash', String(60), nullable=False),
            schema=self.accountsSchemaName,
        )
        Index(
            'unique_user_if_not_deleted',
            table_user_loginmethod_password.c.user_id,
            postgresql_where=table_user_loginmethod_password.c.deleted.is_(None),
            unique=True,
        )
        #### `table_user_loginmethod_passkey` #####################################################################
        #Expresses the user-specific details for the "Passkey" login method.
        table_user_loginmethod_passkey = Table(
            'table_user_loginmethod_passkey',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('creator_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc'::text, now())")),
            Column('deleter_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id')),
            Column('deleted', DateTime(timezone=True)),
            Column('user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('friendly_name', String(100), nullable=True),
            Column('credential_id', sqlalchemy.LargeBinary, nullable=False),
            Column('credential_json', JSON, nullable=False),
            Column('last_used', DateTime(timezone=True), nullable=True),
            schema=self.accountsSchemaName,
        )
        Index(
            'unique_passkey_credential_id_if_not_deleted',
            table_user_loginmethod_passkey.c.credential_id,
            postgresql_where=table_user_loginmethod_passkey.c.deleted.is_(None),
            unique=True,
        )
        #### `table_group_user` ####################################################################
        #Expresses all assignments of users to groups.
        table_group_user = Table(
            'table_group_user',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('creator_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc'::text, now())")),
            Column('deleter_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id')),
            Column('deleted', DateTime(timezone=True)),
            Column('group_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('group_is_group', Boolean, nullable=False, server_default=sqlalchemy.true()),  #Used to enforce `table_group_user.group_user_id` is always a group.
            CheckConstraint('group_is_group IS TRUE', name='check_constraint__table_group_user__group_is_group__true'),
            ForeignKeyConstraint(
                ['group_user_id', 'group_is_group'],
                [f'{self.accountsSchemaName}.table_user.id', f'{self.accountsSchemaName}.table_user.is_group'],
                name='foreign_key_constraint__table_group_user__group_must_be_group',
            ),
            schema=self.accountsSchemaName,
        )
        Index(
            'uniqueindex__group_user_id__user_id__if_not_deleted',
            table_group_user.c.group_user_id,
            table_group_user.c.user_id,
            postgresql_where=table_group_user.c.deleted.is_(None),
            unique=True,
        )
        Index(  #Performance index for user membership lookups.
            'index__table_group_user__user_id_not_deleted',
            table_group_user.c.user_id,
            postgresql_where=table_group_user.c.deleted.is_(None),
        )
        #### `view_group_user` #####################################################
        #Expresses all assignments of specific privileges to specific users.
        create_view_group_user = DDL(d(f"""
            CREATE OR REPLACE VIEW {self.accountsSchemaName}.view_group_user AS
                WITH RECURSIVE grp AS (
                    -- Seed: direct memberships from each group
                    SELECT
                            gu.group_user_id AS root_group_user_id,
                            gu.user_id       AS member_id,
                            ARRAY[gu.group_user_id, gu.user_id]::int[] AS path
                        FROM {self.accountsSchemaName}.table_group_user gu
                        WHERE gu.deleted IS NULL

                    UNION ALL

                    -- Expand: if the member is itself a group, follow its memberships
                    SELECT
                            g.root_group_user_id,
                            gu2.user_id,
                            g.path || gu2.user_id
                        FROM grp g
                        JOIN {self.accountsSchemaName}.table_user u
                          ON u.id = g.member_id
                         AND u.is_group IS TRUE
                        JOIN {self.accountsSchemaName}.table_group_user gu2
                          ON gu2.deleted IS NULL
                         AND gu2.group_user_id = g.member_id
                        WHERE NOT (gu2.user_id = ANY(g.path)) -- cycle protection
                )
                SELECT DISTINCT
                        g.root_group_user_id AS group_user_id,
                        g.member_id     AS user_id
                    FROM grp g
                    JOIN {self.accountsSchemaName}.table_user u2
                      ON u2.id = g.member_id
                     AND u2.is_group IS FALSE
                    ORDER BY group_user_id, user_id
            ;
        """))
        drop_view_group_user = DDL(d(f"""
            DROP VIEW IF EXISTS {self.accountsSchemaName}.view_group_user;
        """))
        event.listen(metadata, "after_create", create_view_group_user)
        event.listen(metadata, "before_drop", drop_view_group_user)
        #### `table_privilege` ########################################################################
        #Expresses all privileged actions.
        table_privilege = Table(
            'table_privilege',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('creator_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc'::text, now())")),
            Column('deleter_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id')),
            Column('deleted', DateTime(timezone=True)),
            Column('name', String, nullable=False),
            Column('parent_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_privilege.id'), nullable=True),
            schema=self.accountsSchemaName,
        )
        Index(
            'unique_parent_id_name_if_not_deleted',
            sqlalchemy.func.coalesce(table_privilege.c.parent_id, 0),
            table_privilege.c.name,
            postgresql_where=table_privilege.c.deleted.is_(None),
            unique=True,
        )
        #### `table_privilege_group_allow` #############################################
        #Expresses all assignments of privileges to specific groups,
        #with privileges defined as patterns that can match multiple privilege
        #names.
        table_privilege_group_allow = Table(
            'table_privilege_group_allow',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('creator_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc'::text, now())")),
            Column('deleter_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id')),
            Column('deleted', DateTime(timezone=True)),
            Column('group_user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('privilege_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_privilege.id'), nullable=False),
            Column('allow', Boolean, nullable=False),
            schema=self.accountsSchemaName,
        )
        Index(
            'unique__group_user_id__privilege_id__if_not_deleted',
            table_privilege_group_allow.c.group_user_id,
            table_privilege_group_allow.c.privilege_id,
            postgresql_where=table_privilege_group_allow.c.deleted.is_(None),
            unique=True,
        )
        #### `function_user_has_privilege_nocache` #########################################################
        #Utility function for looking up if a user has a given privilege, bypassing any caches.
        create_function_user_has_privilege_nocache = DDL(d(f"""
            CREATE OR REPLACE FUNCTION {self.accountsSchemaName}.function_user_has_privilege_nocache(
                    p_group_user_id       integer,
                    p_privilege_id  integer
            )
                RETURNS boolean
                LANGUAGE sql
                STABLE
                AS $$
                    WITH RECURSIVE
                        -- 1) Build subject list: user (depth 0) + all ancestor groups (depth 1..N)
                        subjects AS (
                            SELECT
                                p_group_user_id::int AS subject_id,
                                0              AS subject_depth,
                                ARRAY[p_group_user_id]::int[] AS path

                            UNION ALL

                            SELECT
                                gu.group_user_id AS subject_id,
                                s.subject_depth + 1 AS subject_depth,
                                s.path || gu.group_user_id
                            FROM subjects s
                            JOIN {self.accountsSchemaName}.table_group_user gu
                              ON gu.deleted IS NULL
                             AND gu.user_id = s.subject_id
                            JOIN {self.accountsSchemaName}.table_user g
                              ON g.id = gu.group_user_id
                             AND g.deleted IS NULL
                             AND g.is_group IS TRUE
                            WHERE NOT (gu.group_user_id = ANY(s.path))  -- cycle protection
                        ),

                        -- 2) Build privilege list: privilege (depth 0) + all ancestor privileges (depth 1..N)
                        privs AS (
                            SELECT
                                p_privilege_id::int AS priv_id,
                                0                   AS priv_depth,
                                ARRAY[p_privilege_id]::int[] AS path

                            UNION ALL

                            SELECT
                                p.parent_id AS priv_id,
                                pr.priv_depth + 1 AS priv_depth,
                                pr.path || p.parent_id
                            FROM privs pr
                            JOIN {self.accountsSchemaName}.table_privilege p
                              ON p.deleted IS NULL
                             AND p.id = pr.priv_id
                            WHERE p.parent_id IS NOT NULL
                              AND NOT (p.parent_id = ANY(pr.path))      -- cycle protection
                        ),

                        -- 3) Find all matching allow/deny rules across (subject, privilege-ancestor)
                        matches AS (
                            SELECT
                                a.allow,
                                s.subject_depth,
                                pr.priv_depth
                            FROM subjects s
                            JOIN privs pr ON true
                            JOIN {self.accountsSchemaName}.table_privilege_group_allow a
                              ON a.deleted IS NULL
                             AND a.group_user_id = s.subject_id
                             AND a.privilege_id = pr.priv_id
                        )

                        -- 4) Return highest-priority match; else FALSE
                        SELECT COALESCE(
                            (
                                SELECT m.allow
                                FROM matches m
                                ORDER BY m.subject_depth ASC, m.priv_depth ASC
                                LIMIT 1
                            ),
                            FALSE
                        )
                    ;
                $$
            ;
        """))
        drop_function_user_has_privilege_nocache = DDL(d(f"""
            DROP FUNCTION IF EXISTS {self.accountsSchemaName}.function_user_has_privilege_nocache(integer, integer)
            ;
        """))
        event.listen(metadata, "after_create", create_function_user_has_privilege_nocache)
        event.listen(metadata, "before_drop", drop_function_user_has_privilege_nocache)
        #### `function_user_has_privilege_nocache_with_rule` ########################################
        #Like `function_user_has_privilege_nocache` but also returns the `table_privilege_group_allow.id`
        #of the winning rule so it can be recorded in `table_privilege_log.privilege_user_allow_id`.
        #Returns NULL for `rule_id` when no matching rule exists (implicit deny).
        create_function_user_has_privilege_nocache_with_rule = DDL(d(f"""
            CREATE OR REPLACE FUNCTION {self.accountsSchemaName}.function_user_has_privilege_nocache_with_rule(
                    p_group_user_id  integer,
                    p_privilege_id   integer,
                    OUT allowed      boolean,
                    OUT rule_id      integer
            )
                RETURNS RECORD
                LANGUAGE sql
                STABLE
                AS $$
                    WITH RECURSIVE
                        -- 1) Build subject list: user (depth 0) + all ancestor groups (depth 1..N)
                        subjects AS (
                            SELECT
                                p_group_user_id::int AS subject_id,
                                0              AS subject_depth,
                                ARRAY[p_group_user_id]::int[] AS path

                            UNION ALL

                            SELECT
                                gu.group_user_id AS subject_id,
                                s.subject_depth + 1 AS subject_depth,
                                s.path || gu.group_user_id
                            FROM subjects s
                            JOIN {self.accountsSchemaName}.table_group_user gu
                              ON gu.deleted IS NULL
                             AND gu.user_id = s.subject_id
                            JOIN {self.accountsSchemaName}.table_user g
                              ON g.id = gu.group_user_id
                             AND g.deleted IS NULL
                             AND g.is_group IS TRUE
                            WHERE NOT (gu.group_user_id = ANY(s.path))  -- cycle protection
                        ),

                        -- 2) Build privilege list: privilege (depth 0) + all ancestor privileges (depth 1..N)
                        privs AS (
                            SELECT
                                p_privilege_id::int AS priv_id,
                                0                   AS priv_depth,
                                ARRAY[p_privilege_id]::int[] AS path

                            UNION ALL

                            SELECT
                                p.parent_id AS priv_id,
                                pr.priv_depth + 1 AS priv_depth,
                                pr.path || p.parent_id
                            FROM privs pr
                            JOIN {self.accountsSchemaName}.table_privilege p
                              ON p.deleted IS NULL
                             AND p.id = pr.priv_id
                            WHERE p.parent_id IS NOT NULL
                              AND NOT (p.parent_id = ANY(pr.path))      -- cycle protection
                        ),

                        -- 3) Find all matching allow/deny rules across (subject, privilege-ancestor)
                        matches AS (
                            SELECT
                                a.id      AS rule_id,
                                a.allow,
                                s.subject_depth,
                                pr.priv_depth
                            FROM subjects s
                            JOIN privs pr ON true
                            JOIN {self.accountsSchemaName}.table_privilege_group_allow a
                              ON a.deleted IS NULL
                             AND a.group_user_id = s.subject_id
                             AND a.privilege_id = pr.priv_id
                        ),

                        -- 4) Highest-priority match (most-specific subject, then most-specific privilege)
                        winner AS (
                            SELECT rule_id, allow
                            FROM matches
                            ORDER BY subject_depth ASC, priv_depth ASC
                            LIMIT 1
                        )

                        SELECT
                            COALESCE((SELECT allow    FROM winner), FALSE),
                            (SELECT rule_id FROM winner)
                    ;
                $$
            ;
        """))
        drop_function_user_has_privilege_nocache_with_rule = DDL(d(f"""
            DROP FUNCTION IF EXISTS {self.accountsSchemaName}.function_user_has_privilege_nocache_with_rule(integer, integer)
            ;
        """))
        event.listen(metadata, "after_create", create_function_user_has_privilege_nocache_with_rule)
        event.listen(metadata, "before_drop", drop_function_user_has_privilege_nocache_with_rule)
        #### `view_privilege_group_allow_cache` #####################################################
        #Expresses all assignments of specific privileges to specific groups.
        create_view_privilege_group_allow_cache = DDL(d(f"""
            CREATE MATERIALIZED VIEW {self.accountsSchemaName}.view_privilege_group_allow_cache
                AS
                    SELECT
                        u.id AS group_user_id
                        , p.id AS privilege_id
                        , {self.accountsSchemaName}.function_user_has_privilege_nocache(u.id, p.id) AS privilege_allow
                    FROM {self.accountsSchemaName}.table_user u
                    CROSS JOIN {self.accountsSchemaName}.table_privilege p
                    WHERE u.deleted IS NULL
                        AND u.is_disabled IS FALSE
                        AND u.is_group IS TRUE
                        AND p.deleted IS NULL
                    WITH NO DATA
            ;
            REFRESH MATERIALIZED VIEW {self.accountsSchemaName}.view_privilege_group_allow_cache\
            ;
            CREATE UNIQUE INDEX uniqueindex__view_privilege_group_allow_cache
                ON {self.accountsSchemaName}.view_privilege_group_allow_cache(group_user_id, privilege_id)
            ;
            -- Optional, but often helpful if you filter by privilege:
            CREATE INDEX index__view_privilege_group_allow_cache__by_privilege
                ON {self.accountsSchemaName}.view_privilege_group_allow_cache(privilege_id, group_user_id)
            ;
            CREATE TABLE IF NOT EXISTS {self.accountsSchemaName}.view_privilege_group_allow_cache__is_dirty (
                    id boolean PRIMARY KEY DEFAULT true,
                    dirty boolean NOT NULL,
                    updated_at timestamptz NOT NULL DEFAULT now()
                )
            ;
            CREATE OR REPLACE FUNCTION {self.accountsSchemaName}.function__view_privilege_group_allow_cache__refresh()
                RETURNS void
                LANGUAGE plpgsql
                AS $$
                    BEGIN
                        REFRESH MATERIALIZED VIEW CONCURRENTLY {self.accountsSchemaName}.view_privilege_group_allow_cache
                        ;
                        UPDATE {self.accountsSchemaName}.view_privilege_group_allow_cache__is_dirty
                            SET dirty = false, updated_at = now()
                            WHERE id = true
                        ;
                        END
                    ;
                $$
            ;
            -- Ensure a single row exists:
            INSERT INTO {self.accountsSchemaName}.view_privilege_group_allow_cache__is_dirty(id, dirty)
                VALUES (true, true)
                ON CONFLICT (id) DO NOTHING
            ;
            CREATE OR REPLACE FUNCTION {self.accountsSchemaName}.function__view_privilege_group_allow_cache__is_dirty__setTrue()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                    BEGIN
                        UPDATE {self.accountsSchemaName}.view_privilege_group_allow_cache__is_dirty
                            SET dirty = true, updated_at = now()
                            WHERE id = true
                        ;
                        -- Optional: also notify listeners (app can LISTEN and refresh)
                        PERFORM pg_notify('view_privilege_group_allow_cache__is_dirty', '1')
                        ;
                        RETURN NULL
                        ;
                    END
                    ;
                $$
            ;
            -- Update on `table_privilege` modification.
            DROP TRIGGER IF EXISTS trigger__view_privilege_group_allow_cache__is_dirty__on__table_privilege ON {self.accountsSchemaName}.table_privilege
            ;
            CREATE TRIGGER trigger__view_privilege_group_allow_cache__is_dirty__on__table_privilege
                AFTER INSERT OR UPDATE OR DELETE ON {self.accountsSchemaName}.table_privilege
                FOR EACH STATEMENT
                EXECUTE FUNCTION {self.accountsSchemaName}.function__view_privilege_group_allow_cache__is_dirty__setTrue()
            ;
            -- Update on `table_privilege_group_allow` modification.
            DROP TRIGGER IF EXISTS trigger__view_privilege_group_allow_cache__is_dirty__on__table_privilege_group_allow ON {self.accountsSchemaName}.table_privilege_group_allow
            ;
            CREATE TRIGGER trigger__view_privilege_group_allow_cache__is_dirty__on__table_privilege_group_allow
                AFTER INSERT OR UPDATE OR DELETE ON {self.accountsSchemaName}.table_privilege_group_allow
                FOR EACH STATEMENT
                EXECUTE FUNCTION {self.accountsSchemaName}.function__view_privilege_group_allow_cache__is_dirty__setTrue()
            ;
            -- Update on `table_user` modification.
            DROP TRIGGER IF EXISTS trigger__view_privilege_group_allow_cache__is_dirty__on__table_user__insert_update ON {self.accountsSchemaName}.table_user
            ;
            -- INSERT / UPDATE trigger
            CREATE TRIGGER trigger__view_privilege_group_allow_cache__is_dirty__on__table_user__insert_update
                AFTER INSERT OR UPDATE ON {self.accountsSchemaName}.table_user
                FOR EACH ROW
                WHEN (NEW.is_group IS TRUE)
                EXECUTE FUNCTION {self.accountsSchemaName}.function__view_privilege_group_allow_cache__is_dirty__setTrue()
            ;
            -- DELETE trigger
            DROP TRIGGER IF EXISTS trigger__view_privilege_group_allow_cache__is_dirty__on__table_user__delete ON {self.accountsSchemaName}.table_user
            ;
            CREATE TRIGGER trigger__view_privilege_group_allow_cache__is_dirty__on__table_user__delete
                AFTER DELETE ON {self.accountsSchemaName}.table_user
                FOR EACH ROW
                WHEN (OLD.is_group IS TRUE)
                EXECUTE FUNCTION {self.accountsSchemaName}.function__view_privilege_group_allow_cache__is_dirty__setTrue()
            ;

            -- Update on `table_group_user` modification.
            DROP TRIGGER IF EXISTS trigger__view_privilege_group_allow_cache__is_dirty__on__table_group_user ON {self.accountsSchemaName}.table_group_user
            ;
            CREATE TRIGGER trigger__view_privilege_group_allow_cache__is_dirty__on__table_group_user
                AFTER INSERT OR UPDATE OR DELETE ON {self.accountsSchemaName}.table_group_user
                FOR EACH STATEMENT
                EXECUTE FUNCTION {self.accountsSchemaName}.function__view_privilege_group_allow_cache__is_dirty__setTrue()
            ;
        """))
        drop_view_privilege_group_allow_cache = DDL(d(f"""
            DROP FUNCTION IF EXISTS {self.accountsSchemaName}.function__view_privilege_group_allow_cache__refresh()
            ;
            DROP VIEW IF EXISTS {self.accountsSchemaName}.view_privilege_group_allow_cache
            ;
        """))
        event.listen(metadata, "after_create", create_view_privilege_group_allow_cache)
        event.listen(metadata, "before_drop", drop_view_privilege_group_allow_cache)
        #### `function_user_has_privilege` #########################################################
        #Utility function for looking up if a user has a given privilege, using the cache.
        create_function_user_has_privilege = DDL(d(f"""
            CREATE OR REPLACE FUNCTION {self.accountsSchemaName}.function_user_has_privilege(
                    p_user_id      integer
                    , p_privilege_id integer
                )
                RETURNS boolean
                LANGUAGE plpgsql
                STABLE
                AS $$
                    DECLARE
                        v_is_dirty boolean
                    ;
                    BEGIN
                        -- If the row is missing for any reason, treat as dirty (safe default).
                        SELECT d.dirty
                            INTO v_is_dirty
                            FROM {self.accountsSchemaName}.view_privilege_group_allow_cache__is_dirty d
                            WHERE d.id = true
                        ;
                        IF v_is_dirty IS DISTINCT FROM FALSE THEN
                                -- Cache dirty (or missing): fall back to full resolver.
                                RETURN {self.accountsSchemaName}.function_user_has_privilege_nocache(p_user_id, p_privilege_id)
                                ;
                            END IF
                        ;
                        -- Cache clean: use MV
                        RETURN COALESCE((
                            SELECT bool_and(mv.privilege_allow)
                                FROM {self.accountsSchemaName}.view_privilege_group_allow_cache mv
                                JOIN {self.accountsSchemaName}.table_group_user gr
                                    ON gr.group_user_id = mv.group_user_id
                                JOIN {self.accountsSchemaName}.table_user u
                                    ON u.id = gr.user_id
                                WHERE gr.user_id = p_user_id
                                    AND gr.deleted IS NULL
                                    AND mv.privilege_id = p_privilege_id
                                    AND u.deleted IS NULL
                                    AND u.is_disabled IS FALSE
                                    AND (
                                        u.unlocked IS NULL
                                        OR u.unlocked <= timezone('utc'::text, now())
                                    )
                            ), FALSE)
                        ;
                        END
                    ;
                $$
            ;
        """))
        drop_function_user_has_privilege = DDL(d(f"""
            DROP FUNCTION IF EXISTS {self.accountsSchemaName}.function_user_has_privilege(integer, integer)
            ;
        """))
        event.listen(metadata, "after_create", create_function_user_has_privilege)
        event.listen(metadata, "before_drop", drop_function_user_has_privilege)
        #### `function_group_has_privilege` #########################################################
        #Utility function for looking up if a group has a given privilege, using the cache.
        create_function_group_has_privilege = DDL(d(f"""
            CREATE OR REPLACE FUNCTION {self.accountsSchemaName}.function_group_has_privilege(
                    p_group_user_id      integer,
                    p_privilege_id integer
                )
                RETURNS boolean
                LANGUAGE plpgsql
                STABLE
                AS $$
                    DECLARE
                        v_is_dirty boolean
                    ;
                    BEGIN
                        -- If the row is missing for any reason, treat as dirty (safe default).
                        SELECT d.dirty
                            INTO v_is_dirty
                            FROM {self.accountsSchemaName}.view_privilege_group_allow_cache__is_dirty d
                            WHERE d.id = true
                        ;
                        IF v_is_dirty IS DISTINCT FROM false THEN
                                -- Cache dirty (or missing): fall back to full resolver
                                RETURN {self.accountsSchemaName}.function_user_has_privilege_nocache(p_group_user_id, p_privilege_id)
                                ;
                            END IF
                        ;
                        -- Cache clean: use MV
                        RETURN EXISTS (
                                SELECT 1
                                    FROM {self.accountsSchemaName}.view_privilege_group_allow_cache mv
                                    WHERE mv.group_user_id = p_group_user_id
                                    AND mv.privilege_id = p_privilege_id
                            )
                        ;
                        END
                    ;
                $$
            ;
        """))
        drop_function_group_has_privilege = DDL(d(f"""
            DROP FUNCTION IF EXISTS {self.accountsSchemaName}.function_group_has_privilege(integer, integer)
            ;
        """))
        event.listen(metadata, "after_create", create_function_group_has_privilege)
        event.listen(metadata, "before_drop", drop_function_group_has_privilege)
        #### `table_privilege_user_log` ####################################################################
        #Log of all privileged actions granted or denied.
        table_privilege_log = Table(
            'table_privilege_log',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc'::text, now())")),  #Time that the privilege was requested.
            Column('privilege_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_privilege.id'), nullable=False),  #Specific privilege being requested.
            Column('privilege_user_allow_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_privilege_group_allow.id'), nullable=True),  #Specific rule used to make the ALLOW/DENY decision.  May be NULL if privilege was denied due to no applicable "ALLOW" rule.
            Column('session_id', Integer, ForeignKey(f'{self.sessionsSchemaName}.table_session.id'), nullable=False),  #Login session requesting the privilege.
            Column('allowed', Boolean, nullable=False),  #`TRUE` if the privilege was granted; `FALSE` if denied.
            schema=self.sessionsSchemaName,
        )
        #### `table_session` ####################################################################
        #Expresses user login sessions, both expired and active.
        Table(
            'table_session',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('created', DateTime(timezone=True), server_default=text("timezone('utc'::text, now())")),
            Column('deleted', DateTime(timezone=True)),
            Column('expires', DateTime(timezone=True), server_default=text("timezone('utc'::text, (now() + '12:00:00'::interval))")),
            Column('cookie_id', BigInteger, unique=True),  #The cookie ID for Internet browser sessions.  May be NULL for API sessions.
            Column('user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=False),
            Column('remember_me', Boolean, nullable=False, server_default=text('FALSE')),  #TRUE if the user checked "Remember Me" at login; session expires in 30 days and is not subject to idle timeout.
            Column('last_active', DateTime(timezone=True)),  #Updated (at most every 5 min) on each authenticated request; used to enforce the 2-hour idle timeout for non-remembered sessions.
            schema=self.sessionsSchemaName,
        )
        create_idx_table_session_user_active = DDL(d(f"""
            CREATE INDEX IF NOT EXISTS idx_table_session_user_active
                ON {self.sessionsSchemaName}.table_session (user_id, last_active)
                WHERE deleted IS NULL
            ;
        """))
        drop_idx_table_session_user_active = DDL(d(f"""
            DROP INDEX IF EXISTS {self.sessionsSchemaName}.idx_table_session_user_active
            ;
        """))
        event.listen(metadata, 'after_create', create_idx_table_session_user_active)
        event.listen(metadata, 'before_drop', drop_idx_table_session_user_active)
        #### `view_session_active` #####################################################
        #Expresses all active user login sessions.
        create_view_session_active = DDL(d(f"""
            CREATE OR REPLACE VIEW {self.sessionsSchemaName}.view_session_active
                AS WITH t AS (SELECT timezone('utc'::text, now()) AS now_utc)
                    SELECT
                            table_session.*
                        FROM t, {self.sessionsSchemaName}.table_session
                        JOIN {self.accountsSchemaName}.table_user
                            ON table_user.id = table_session.user_id
                        WHERE table_session.deleted IS NULL
                            AND table_session.expires > t.now_utc
                            AND table_user.is_disabled = FALSE
                            AND (
                                table_user.unlocked IS NULL
                                OR table_user.unlocked <= t.now_utc
                            )
                            AND (
                                table_session.remember_me = TRUE
                                OR COALESCE(table_session.last_active, table_session.created) > t.now_utc - interval '2 hours'
                            )
            ;
        """))
        drop_view_session_active = DDL(d(f"""
            DROP VIEW IF EXISTS {self.sessionsSchemaName}.view_session_active
            ;
        """))
        event.listen(metadata, "after_create", create_view_session_active)
        event.listen(metadata, "before_drop", drop_view_session_active)
        #### `table_user_login` ####################################################################
        #Log of all user login attempts.
        #
        #AFTER `table_session` for the foreign key dependency.
        table_user_login = Table(
            'table_user_login',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc'::text, now())")),
            Column('user_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_user.id'), nullable=True),  #User ID associated with the login.  May be `NULL` if a user could not be resolved from the provided login details.
            Column('loginmethod_id', Integer, ForeignKey(f'{self.accountsSchemaName}.table_loginmethod.id'), nullable=False),
            Column('loginmethod_details', JSON, nullable=True),  #Useful details on the login (e.g. IP address, user agent)
            Column('is_success', Boolean, nullable=False),  #`TRUE` if the login attempt was successful; `false` otherwise.
            Column('session_id', Integer, ForeignKey(f'{self.sessionsSchemaName}.table_session.id'), nullable=True),  #Session created for a successful login (`success = TRUE`); `NULL` for failed logins (`success = FALSE`).
            Column('unlocked', DateTime(timezone=True), nullable=True),  #If not `NULL`, then the login attempt resulted in a lockout until this date/time (`table_user.unlocked = table_user_login.unlocked`).  Usually a result of too many failed logins in a row (`success = FALSE`).
            schema=self.accountsSchemaName,
        )
        create_idx_user_login_ip = DDL(d(f"""
            CREATE INDEX IF NOT EXISTS idx_user_login_ip
                ON {self.accountsSchemaName}.table_user_login ((loginmethod_details->>'ip'))
            ;
        """))
        drop_idx_user_login_ip = DDL(d(f"""
            DROP INDEX IF EXISTS {self.accountsSchemaName}.idx_user_login_ip
            ;
        """))
        event.listen(metadata, 'after_create', create_idx_user_login_ip)
        event.listen(metadata, 'before_drop', drop_idx_user_login_ip)

    def table_group_user__record_create(
            self,
            connection :Connection,
            creator_user_id :int,
            group_user_id :int,
            user_id :int,
    ) ->int|None:
        """
        Creates a record with the given information and returns its
        `table_group_user.id` value.

        Returns `None` on error.
        """
        ret = None
        try:
            insert_sql = text(d(f"""
                INSERT INTO {self.accountsSchemaName}.table_group_user (
                        creator_user_id
                        , group_user_id
                        , user_id
                    )
                    VALUES (
                        :creator_user_id
                        , :group_user_id
                        , :user_id
                    )
                    RETURNING id
                ;
            """))
            ret = connection.execute(insert_sql, {
                'creator_user_id': creator_user_id,
                'group_user_id': group_user_id,
                'user_id': user_id,
            }).scalar_one()
            print(f'Group-User record created successfully: {group_user_id=}; {user_id=}')
        except SQLAlchemyError as e:
            print(f'ERROR creating record "{creator_user_id=}; {group_user_id=}; {user_id=}": {e}')
            raise
        return ret

    def table_loginmethod__record_create(
            self,
            connection :Connection,
            creator_user_id :int,
            loginmethod :LoginMethod,
    ) ->int|None:
        """
        Creates a record with the given information and returns its
        `table_loginmethod.id` value.

        Returns `None` on error.
        """
        ret = None
        try:
            insert_sql = text(d(f"""
                INSERT INTO {self.accountsSchemaName}.table_loginmethod (
                        creator_user_id
                        , name
                    )
                    VALUES (
                        :creator_user_id
                        , :loginmethod_name
                    )
                    RETURNING id
                ;
            """))
            ret = connection.execute(insert_sql, {
                'creator_user_id': creator_user_id,
                'loginmethod_name': loginmethod.value,
            }).scalar_one()
            print(f'Record created successfully.')
        except SQLAlchemyError as e:
            print(f'ERROR creating record ({creator_user_id=}; {loginmethod=}): {e}')
            raise
        return ret

    def table_user_init(
            self,
            connection :Connection,
            root__email :str,
            root__phone_sms :str,
    ) ->tuple[str|None, str|None]:
        """
        Initializes `table_user` with a root user account belonging to a group
        named "sudoers" and the essential privileges for a root user.

        Returns a 2-tuple:
            - Username
            - Password
        """
        ret_password = None
        ret_username = None
        if not self.table_exists(connection, self.accountsSchemaName, 'table_user'):
            tableCreate(connection, self.accountsSchemaName, table_user)
        connection.execute(  #Purge any existing records.
            text(d(f"""
                DELETE FROM {self.accountsSchemaName}.table_privilege
                ;
                DELETE FROM {self.accountsSchemaName}.table_privilege_group_allow
                ;
                DELETE FROM {self.accountsSchemaName}.table_group_user
                ;
                DELETE FROM {self.accountsSchemaName}.table_loginmethod
                ;
                DELETE FROM {self.accountsSchemaName}.table_user_loginmethod
                ;
                DELETE FROM {self.accountsSchemaName}.table_user_loginmethod_password
                ;
                DELETE FROM {self.accountsSchemaName}.table_user_loginmethod_passkey
                ;
                DELETE FROM {self.accountsSchemaName}.table_user  --Always last to avoid foreign key conflicts.
                ;
            """))
        )
        if True:  #Create the root user and "sudoers" group.
            #Generate a random username for the initial admin
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            root__username = f'root_{random_suffix}'
            #Generate a strong random password
            password_characters = string.ascii_letters + string.digits + string.punctuation
            root__password = ''.join(random.choice(password_characters) for i in range(16))
            root__user_id = self.table_user__record_create(  #Create the root account.
                connection,
                None,  #Creates itself.
                root__username,
                'I Am Root',
                root__email,
                root__phone_sms,
                False,  #`is_group`
            )
            loginmethod_id = self.table_loginmethod__record_create(
                connection,
                root__user_id,
                self.LoginMethod.Password,
            )
            self.table_loginmethod__record_create(
                connection,
                root__user_id,
                self.LoginMethod.Passkey,
            )
            self.table_user_loginmethod__record_create(
                connection,
                root__user_id,
                self.LoginMethod.Password,
            )
            self.table_user_loginmethod_password__record_create(  #Assign a password to the root account.
                connection,
                root__user_id,
                root__password,
            )
            ret_username = root__username
            ret_password = root__password
            sudoers__user_id = self.table_user__record_create(  #Create the "sudoers" group.
                connection,
                root__user_id,  #`creator_user_id`
                'sudoers',  #`username`
                'sudoers',  #`name_display`
                '',  #`email`
                '',  #`phone_sms`
                True,  #`is_group`
            )
            self.table_group_user__record_create(  #Assign the root user to the "sudoers" group.
                connection,
                root__user_id,
                sudoers__user_id,
                root__user_id,
            )
            privilege_sudo_id = self.table_privilege__record_create(  #Create the "sudo" privilege.
                connection,
                root__user_id,  #`creator_user_id`
                "sudo",  #`name`
                None, #`parent_id`
            )
            privilege_sudoers_ids = self.table_privilege__privilege_create(  #Create the "sudo/sudoers/*" privileges.
                connection,
                root__user_id,  #`creator_user_id`
                "sudoers",  #`name`
                privilege_sudo_id, #`parent_id`
            )
            privilege_users_ids = self.table_privilege__privilege_create(  #Create the "sudo/users/*" privileges.
                connection,
                root__user_id,  #`creator_user_id`
                "users",  #`name`
                privilege_sudo_id, #`parent_id`
            )
            privilege_groups_ids = self.table_privilege__privilege_create(  #Create the "sudo/groups/*" privileges.
                connection,
                root__user_id,  #`creator_user_id`
                "groups",  #`name`
                privilege_sudo_id, #`parent_id`
            )
            self.table_privilege__record_create(  #Create the "sudo/groups/update/name" privilege.
                connection,
                root__user_id,  #`creator_user_id`
                "name",  #`name`
                privilege_groups_ids[1][2], #`parent_id`
            )
            self.table_privilege__record_create(  #Create the "sudo/groups/update/users" privilege.
                connection,
                root__user_id,  #`creator_user_id`
                "users",  #`name`
                privilege_groups_ids[1][2], #`parent_id`
            )
            self.table_privilege__record_create(  #Create the "sudo/groups/update/privileges" privilege.
                connection,
                root__user_id,  #`creator_user_id`
                "privileges",  #`name`
                privilege_groups_ids[1][2], #`parent_id`
            )
            privilege__groups_users__ids = self.table_privilege__privilege_create(  #Create the "sudo/groups_users/*" privileges.
                connection,
                root__user_id,  #`creator_user_id`
                "groups_users",  #`name`
                privilege_sudo_id, #`parent_id`
            )
            privilege_privileges_ids = self.table_privilege__privilege_create(  #Create the "sudo/privileges" privilege.
                connection,
                root__user_id,  #`creator_user_id`
                "privileges",  #`name`
                privilege_sudo_id, #`parent_id`
            )
            privilege__privileges_groups__ids = self.table_privilege__privilege_create(  #Create the "sudo/privileges_groups" privilege.
                connection,
                root__user_id,  #`creator_user_id`
                "privileges_groups",  #`name`
                privilege_sudo_id, #`parent_id`
            )
            self.table_privilege_group_allow__record_create(  #Assign the "sudo" privilege to the "sudoers" group.
                connection,
                root__user_id,  #`creator_user_id`
                sudoers__user_id,  #`group_user_id`
                privilege_sudo_id,  #`privilege_id`
                True, #`allow`
            )
        return (ret_username, ret_password)

    def table_user__record_create(
            self,
            connection :Connection,
            creator_user_id :int|None,
            username :str,
            name_display :str,
            email :str,
            phone_sms :str,
            is_group :bool,
    ) ->int|None:
        """
        Creates a record with the given information and returns its
        `table_user.id` value.

        If `creator_user_id` is `None`, this the row's new ID will be used
        (account created itself).

        Returns `None` on error.
        """
        ret = None
        try:
            if creator_user_id is None:
                connection.execute(text(d(f"""
                    SET CONSTRAINTS
                        {self.accountsSchemaName}.foreign_key_constraint__table_user__creator_must_be_user
                        DEFERRED
                    ;
                """)))
                ret = connection.execute(
                    text(d(f"""
                        INSERT INTO {self.accountsSchemaName}.table_user
                            (
                                creator_user_id
                                , username
                                , name_display
                                , email
                                , phone_sms
                                , is_group
                                , is_loginenabled
                                , is_disabled
                            )
                            VALUES (
                                -1
                                , :username
                                , :name_display
                                , :email
                                , :phone_sms
                                , :is_group
                                , :is_loginenabled
                                , FALSE
                            )
                            RETURNING id
                        ;
                    """)), {
                    'username': username,
                    'name_display': name_display,
                    'email': email,
                    'phone_sms': phone_sms,
                    'is_group': is_group,
                    'is_loginenabled': not is_group,
                }).scalar_one()
                updated_id = connection.execute(
                    text(d(f"""
                        UPDATE {self.accountsSchemaName}.table_user u
                            SET creator_user_id = :user_id
                            WHERE u.id = :user_id
                            RETURNING u.id
                        ;
                    """)), {
                    'user_id': ret,
                }).scalar_one()
                assert(updated_id == ret)
            else:
                insert_sql = f"""
                    INSERT INTO {self.accountsSchemaName}.table_user (
                            creator_user_id
                            , username
                            , name_display
                            , email
                            , phone_sms
                            , is_group
                            , is_loginenabled
                            , is_disabled
                        )
                        VALUES (
                            :creator_user_id
                            , :username
                            , :name_display
                            , :email
                            , :phone_sms
                            , :is_group
                            , :is_loginenabled
                            , FALSE
                        )
                        RETURNING id
                    ;
                """
                ret = connection.execute(text(insert_sql), {
                    'creator_user_id': creator_user_id,
                    'username': username,
                    'name_display': name_display,
                    'email': email,
                    'phone_sms': phone_sms,
                    'is_group': is_group,
                    'is_loginenabled': not is_group,
                }).scalar_one()
            print(f'User "{username}" created successfully.')
        except SQLAlchemyError as e:
            print(f'ERROR creating user "{username}": {e}')
            raise
        return ret

    def table_user_loginmethod__record_create(
            self,
            connection :Connection,
            user_id :int,
            loginmethod :LoginMethod,
    ) ->int|None:
        """
        Creates a record with the given information and returns its
        `table_user_loginmethod_password.id` value.

        Returns `None` on error.
        """
        ret = None
        try:
            insert_sql = text(d(f"""
                INSERT INTO {self.accountsSchemaName}.table_user_loginmethod (
                        creator_user_id
                        , user_id
                        , loginmethod_id
                    )
                    VALUES (:user_id, :user_id, (
                        SELECT table_loginmethod.id
                        FROM {self.accountsSchemaName}.table_loginmethod
                        WHERE table_loginmethod.name = :loginmethod_name
                    ))
                    RETURNING id
                ;
            """))
            ret = connection.execute(insert_sql, {
                'user_id': user_id,
                'loginmethod_name': loginmethod.value,
            }).scalar_one()
            print(f'User login method created successfully: {user_id=}; {loginmethod.value=}; loginmethod_id={ret}')
        except SQLAlchemyError as e:
            print(f'ERROR creating user login method: {user_id=}; {loginmethod.value=}; {e}')
            raise
        return ret

    def table_user_loginmethod_password__record_create(
            self,
            connection :Connection,
            user_id :int,
            password :str,
    ) ->int|None:
        """
        Creates a record with the given information and returns its
        `table_user_loginmethod_password.id` value.

        Returns `None` on error.
        """
        ret = None
        try:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            insert_sql = text(d(f"""
                INSERT INTO {self.accountsSchemaName}.table_user_loginmethod_password (
                        creator_user_id
                        , user_id
                        , password_hash
                    )
                    VALUES (:user_id, :user_id, :password_hash)
                    RETURNING id
                ;
            """))
            ret = connection.execute(insert_sql, {
                'user_id': user_id,
                'password_hash': password_hash,
            }).scalar_one()
            print(f'Password created successfully: {user_id=}')
        except SQLAlchemyError as e:
            print(f'ERROR creating password: {user_id=}; {e}')
            raise
        return ret

    def table_privilege__privilege_create(
            self,
            connection :Connection,
            creator_user_id :int,
            privilege_name :str,
            parent_id :int|None,
    ) ->tuple[int, tuple[int, int, int, int]]|None:
        """
        Creates a privilege with the given information.

        Unlike `self.table_privilege__record_create(...)`, this will create the
        root privilege and CRUD sub-privileges:
            - "create"
            - "read"
            - "update"
            - "delete"

        Returns `None` on error, or a tuple on success.
        """
        ret = self.table_privilege__record_create(
            connection
            , creator_user_id
            , privilege_name
            , parent_id
        )
        if ret is not None:  #Create the CRUD.
            ret_create = self.table_privilege__record_create(
                connection
                , creator_user_id
                , "create"
                , ret
            )
            ret_read = self.table_privilege__record_create(
                connection
                , creator_user_id
                , "read"
                , ret
            )
            ret_update = self.table_privilege__record_create(
                connection
                , creator_user_id
                , "update"
                , ret
            )
            ret_delete = self.table_privilege__record_create(
                connection
                , creator_user_id
                , "delete"
                , ret
            )
        return (ret, (ret_create, ret_read, ret_update, ret_delete))

    def table_privilege__record_create(
            self,
            connection :Connection,
            creator_user_id :int,
            name :str,
            parent_id :int|None,
    ) ->int|None:
        """
        Creates a record with the given information and returns its
        `table_privilege.id` value.

        Returns `None` on error.
        """
        ret = None
        try:
            insert_sql = text(d(f"""
                INSERT INTO {self.accountsSchemaName}.table_privilege (
                        creator_user_id
                        , name
                        , parent_id
                    )
                    VALUES (:creator_user_id, :name, :parent_id)
                    RETURNING id
                ;
            """))
            ret = connection.execute(insert_sql, {
                'creator_user_id': creator_user_id,
                'name': name,
                'parent_id': parent_id,
            }).scalar_one()
            print(f'Privilege created successfully: {name=}; {parent_id=}')
        except SQLAlchemyError as e:
            print(f'ERROR creating privilege: {creator_user_id=}; {name=}; {e}')
            raise
        return ret

    def table_privilege_group_allow__record_create(
            self,
            connection :Connection,
            creator_user_id :int,
            group_user_id :int,
            privilege_id :int,
            allow :bool,
    ) ->int|None:
        """
        Creates a record with the given information and returns its
        `table_privilege_group_allow.id` value.

        Returns `None` on error.
        """
        ret = None
        try:
            insert_sql = text(d(f"""
                INSERT INTO {self.accountsSchemaName}.table_privilege_group_allow (
                        creator_user_id
                        , group_user_id
                        , privilege_id
                        , allow
                    )
                    VALUES (:creator_user_id, :group_user_id, :privilege_id, :allow)
                    RETURNING id
                ;
            """))
            ret = connection.execute(insert_sql, {
                'creator_user_id': creator_user_id,
                'group_user_id': group_user_id,
                'privilege_id': privilege_id,
                'allow': allow,
            }).scalar_one()
            print(f'Group privilege created successfully: {group_user_id=}; {privilege_id=}; {allow=}')
        except SQLAlchemyError as e:
            print(f'ERROR creating group privilege: {group_user_id=}; {privilege_id=}; {e}')
            raise
        return ret

    def tableAdmin_rootUserExists(self, connection :Connection, schema :str, table :str) ->bool:
        query = text(f'SELECT 1 FROM {schema}.{table} WHERE username LIKE :pattern;')
        result = connection.execute(query, {'pattern': 'root%'}).fetchone()
        return (result is not None)

    def view_privilege_group_allow_cache__refresh(self, connection :Connection) ->bool:
        query = text(f'SELECT {self.accountsSchemaName}.function__view_privilege_group_allow_cache__refresh();')
        result = connection.execute(query).fetchone()
        return (result is not None)

class SchemaV0(SchemaV0_Base):

    clsPrev = None

    def __init__(self, *args, **kargs):
        super().__init__(None, None, *args, **kargs)
