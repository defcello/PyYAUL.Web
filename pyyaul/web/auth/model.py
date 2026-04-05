"""
Generic authorization business-logic functions for the auth module.

All functions accept a `dbModelContext` (modules.auth.db.model.DBModelContext
instance) as their first argument so that both adminauth and userauth can
reuse the same logic against their respective databases.
"""

import bcrypt




def authAccountsRecord_make(
        dbModelContext,
        authsession_session_record,
        username :str,
        is_super_auth :bool,
        email :str|None =None,
        name :str|None =None,
        phone_sms :str|None =None,
) ->object:
    """
    Creates a new user account with the provided information and returns the
    ORM record.

    Also wires up the "Username and Password" login method for the new user so
    that a password can be set via `authAccountsRecord_password_set` afterward.

    If `is_super_auth` is `True`, the new user is added to the `sudoers` group
    so they inherit the `sudo` privilege.
    """
    caller_user_id = authsession_session_record.wolc_authaccounts__user__id
    ormRecord = dbModelContext.authaccounts_user_create(
        username=username,
        name=name,
        email=email,
        phone_sms=phone_sms,
        creator_user_id=caller_user_id,
    )
    if ormRecord is None or ormRecord.id is None:
        raise Exception('ERROR Unexpectedly failed to create user account.')
    dbModelContext.authaccounts_user_loginmethod_add(ormRecord.id, caller_user_id)
    if is_super_auth:
        dbModelContext.authaccounts_sudoers_group_user_add(ormRecord.id, caller_user_id)
    return ormRecord


def authAccountsRecord_delete(
        dbModelContext,
        authsession_session_record,
        target_user_id :int,
) ->None:
    """
    Soft-deletes the user matching `target_user_id`.

    Requires the caller to hold the `sudo` privilege.
    """
    caller_user_id = authsession_session_record.wolc_authaccounts__user__id
    if not dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id, ('sudo',),
            session_id=authsession_session_record.wolc_authsession__session__id):
        raise ValueError('ERROR: This operation requires the `sudo` privilege.')
    dbModelContext.authaccounts_user_delete(target_user_id, caller_user_id)


def authAccountsRecord_info_set(
        dbModelContext,
        authsession_session_record,
        target_user_id :int,
        name :str,
        email :str,
        phone_sms :str,
) ->None:
    """
    Updates the display info (name, email, phone) for the user matching
    `target_user_id`.

    Requires the caller to either hold the `sudo` privilege or be the target
    user themselves.
    """
    caller_user_id = authsession_session_record.wolc_authaccounts__user__id
    caller_is_super_auth = dbModelContext.authaccounts_user_allowPrivilege_read(
        caller_user_id, ('sudo',),
        session_id=authsession_session_record.wolc_authsession__session__id,
    )
    if not caller_is_super_auth and caller_user_id != target_user_id:
        raise ValueError(
            'ERROR: This operation requires the `sudo` privilege or being logged in as the account being modified.'
        )
    dbModelContext.authaccounts_user_info_set(target_user_id, name, email, phone_sms)


def authAccountsRecord_isSuperauth_set(
        dbModelContext,
        authsession_session_record,
        target_user_id :int,
        is_super_auth :bool,
) ->None:
    """
    Grants or revokes the `sudo` privilege for the user matching `target_user_id`
    by adding or removing them from the `sudoers` group.

    Requires the caller to hold the `sudo` privilege.
    """
    caller_user_id = authsession_session_record.wolc_authaccounts__user__id
    if not dbModelContext.authaccounts_user_allowPrivilege_read(
            caller_user_id, ('sudo',),
            session_id=authsession_session_record.wolc_authsession__session__id):
        raise ValueError('ERROR: This operation requires the `sudo` privilege.')
    if is_super_auth:
        dbModelContext.authaccounts_sudoers_group_user_add(target_user_id, caller_user_id)
    else:
        dbModelContext.authaccounts_sudoers_group_user_remove(target_user_id, caller_user_id)


def authAccountsRecord_password_set(
        dbModelContext,
        user_id :int,
        password :str,
        min_length :int,
) ->None:
    """
    Hashes and stores a new password for the user matching `user_id`.

    `min_length` is the caller-supplied minimum password length (e.g. from
    `BlueprintContext.password_min_length`); keeping it as a parameter lets
    consuming apps enforce different policies without polluting this generic
    module.

    Raises `ValueError` if the password does not meet the minimum length.
    """
    if not isinstance(password, str):
        raise ValueError(f'`password` is an unexpected type: {type(password)=}')
    if len(password) < min_length:
        raise ValueError(
            f'Passwords must be at least {min_length} characters in length; {len(password)=}'
        )
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    dbModelContext.authaccounts__user__password_hash__set(user_id, password_hash)
