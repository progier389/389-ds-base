# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
"""Entry cache rollback tests

Check what happens to the entry cache and the DN cache when a backend
transaction (betxn) plugin fails. See the "Improving entry cache rollback"
design document (entrycache-rollback.md in the 389ds wiki).

Test ids in the docstrings refer to the design test plan (1.x: skip useless
reverts, 2.x: ownership, 3.x: pinned entries revert).

Tests tagged [new] in the docstring check the improvement and are
expected to fail with the server code from before the improvement.
Tests tagged [both] check correctness and must pass with both versions.

Every log message, error code and plugin trick the tests depend on is
defined in the variables below, so the tests can easily be adapted if the
server code changes.
"""

import os
import re
import time
import logging
import threading
import pytest
import ldap
from lib389._constants import DEFAULT_SUFFIX, DN_DM, PW_DM
from lib389._mapped_object import DSLdapObject
from lib389.backend import Backends
from lib389.config import BDB_LDBMConfig, LMDB_LDBMConfig
from lib389.idm.domain import Domain
from lib389.idm.group import Groups, UniqueGroups, UniqueGroup
from lib389.idm.organizationalunit import OrganizationalUnits
from lib389.idm.user import UserAccounts, UserAccount
from lib389.plugins import (MemberOfPlugin, AttributeUniquenessPlugin,
                            ReferentialIntegrityPlugin)
from lib389.utils import get_default_db_lib
from test389.topologies import topology_st

pytestmark = pytest.mark.tier1

DEBUGGING = os.getenv("DEBUGGING", default=False)
if DEBUGGING:
    logging.getLogger(__name__).setLevel(logging.DEBUG)
else:
    logging.getLogger(__name__).setLevel(logging.INFO)
log = logging.getLogger(__name__)


###########################################################################
# Error log patterns
#
# Python regular expressions, matched with re.search() against each error
# log line. '{dn}' is replaced by the escaped, normalized (lower case)
# DN of the checked entry. Do not use other '{' '}' in these patterns.
# A pattern set to None disables the checks that use it.
###########################################################################

# Logged by flush_hash() each time revert_cache() walks the caches
FLUSH_WARN_LOG = r'WARN - flush_hash - Upon BETXN callback failure, entry cache is flushed'

# Existing nsslapd-cache-debug-pattern (LOGPATTERN) messages
CACHE_ADD_LOG = r'entrycache_add_int - CACHE DEBUG: .* dn:{dn}$'
CACHE_REMOVE_LOG = r'entrycache_remove_int - CACHE DEBUG: .* dn:{dn}$'
PINNED_ADD_LOG = r'pinned_add - CACHE DEBUG: Adding entry {dn} weight'
PINNED_REMOVE_LOG = r'pinned_remove - CACHE DEBUG: Removing entry {dn} weight'

# New LOGPATTERN messages logged by the rollback (see "Logging" in the
# design). The final wording is decided while implementing: adapt these
# patterns, or set them to None to skip the checks.
ROLLBACK_EVICT_LOG = r'(?i)CACHE DEBUG: .*rollback.*evict.*[ :]{dn}(\s|$)'
ROLLBACK_REVERT_LOG = r'(?i)CACHE DEBUG: .*rollback.*revert.*[ :]{dn}(\s|$)'

# Time to wait before reading the error log (some cache messages are
# logged when the entry is released, which may happen after the result
# is sent)
LOG_SETTLE_DELAY = 1

###########################################################################
# Ways to make a betxn plugin fail, and the expected errors
###########################################################################

# betxn pre-op failure: attribute uniqueness on a non-RDN attribute
UNIQUE_ATTR = 'employeeNumber'
UNIQUENESS_ERROR = ldap.CONSTRAINT_VIOLATION

# betxn post-op failure: memberOf cannot add memberOf to a member that has
# no objectclass allowing it, then retries after adding memberOfAutoAddOC,
# which does not allow it either.
MEMBEROF_AUTOADDOC = 'account'
BAD_MEMBER_REMOVED_OC = 'nsMemberOf'   # Removed from the "bad" members
MEMBEROF_ERROR = ldap.OBJECT_CLASS_VIOLATION

# betxn post-op failure on DELETE: referint removes the deleted DN from an
# alias entry, but aliasedObjectName is a MUST attribute of 'alias'
REFERINT_ATTR = 'aliasedObjectName'
ALIAS_OBJECTCLASSES = ['top', 'alias', 'extensibleObject']
REFERINT_ERROR = ldap.OBJECT_CLASS_VIOLATION

###########################################################################
# Test data and cache configuration
###########################################################################

BACKEND_NAME = 'userRoot'
RBTEST_DN = f'ou=rbtest,{DEFAULT_SUFFIX}'       # memberOf and uniqueness scope
RBOUT_DN = f'ou=rbout,{DEFAULT_SUFFIX}'         # out of memberOf scope
PEOPLE_DN = f'ou=people,{RBTEST_DN}'
GROUPS_DN = f'ou=groups,{RBTEST_DN}'
READERS_DN = f'ou=readers,{RBTEST_DN}'
ALIASES_DN = f'ou=aliases,{RBTEST_DN}'
FAKE_MEMBERS_DN = f'ou=fake,{DEFAULT_SUFFIX}'   # Never created
# nsslapd-cache-debug-pattern: logs all the entries under ou=rbtest and ou=rbout
DEBUG_PATTERN = f'.*ou=rb[a-z]*,{DEFAULT_SUFFIX}$'

ENTRY_CACHE_MEMSIZE = str(512 * 1024 * 1024)    # Large enough to avoid LRU eviction
ENTRY_CACHE_SIZE = '-1'
DN_CACHE_MEMSIZE = str(64 * 1024 * 1024)

BIG_GROUP_SIZE = 3000         # Number of uniquemember values of the pinned groups
NB_PINNED = 3                 # nsslapd-cache-pinned-entries (number of big groups)
NB_READERS = 1000             # Entries used by the concurrency tests
MIN_FAILURES = 50             # Minimum number of failing operations in concurrency tests
NB_SUCCESSFUL_MODS = 100      # Successful modifies in the leak test
SUFFIX2 = 'dc=rbtest2,dc=com'
BACKEND2_NAME = 'rbtest2'

PIN_MOD_CN = 'rb-pin-mod'     # Pinned group modified by the tests
PIN_DEL_CN = 'rb-pin-del'     # Pinned group the tests try to delete
PIN_REN_CN = 'rb-pin-ren'     # Pinned group (out of scope) the tests try to move in scope


###########################################################################
# Helpers
###########################################################################

class AliasEntry(DSLdapObject):
    """An alias entry, used to make referint fail on DELETE"""

    def __init__(self, instance, dn=None):
        super(AliasEntry, self).__init__(instance, dn)
        self._rdn_attribute = 'cn'
        self._must_attributes = ['cn', REFERINT_ATTR]
        self._create_objectclasses = ALIAS_OBJECTCLASSES


def create_alias(inst, target_dn):
    """Create an alias entry referencing target_dn (makes referint fail
    when target_dn is deleted)"""
    name = unique_name('rb-alias')
    alias = AliasEntry(inst, f'cn={name},{ALIASES_DN}')
    alias.create(properties={'cn': name, REFERINT_ATTR: target_dn})
    return alias


def ndn(dn):
    """Normalized DN, as logged by the server (no spaces, lower case)"""
    return ','.join(rdn.strip() for rdn in dn.split(',')).lower()


def logpat(template, dn=None, dn_regex=None):
    """Build an error log regex from a template.

    :param dn: Exact DN of the entry
    :param dn_regex: Regex matching the normalized DN (instead of dn)
    """
    if template is None:
        return None
    if dn is not None:
        dn_regex = re.escape(ndn(dn))
    return template.format(dn=dn_regex)


class ErrorLogWindow:
    """Error log lines written after the object was created"""

    def __init__(self, inst):
        self.path = inst.ds_paths.error_log
        self.offset = os.path.getsize(self.path)
        self._lines = None

    def lines(self):
        if self._lines is None:
            time.sleep(LOG_SETTLE_DELAY)
            with open(self.path, 'r', errors='replace') as f:
                f.seek(self.offset)
                self._lines = f.read().splitlines()
        return self._lines

    def match(self, pattern):
        if pattern is None:
            return []
        lines = self.lines()
        text = '\n'.join(lines)
        log.info(f'*** Looking for pattern {pattern} in\n{text}\n***')
        prog = re.compile(pattern)
        res = [line for line in lines if prog.search(line)]
        log.debug(f'ErrorLogWindow.match({pattern}) returns {res}')
        return res


def retry_if_busy(f, *args, **kwargs):
    for _ in range(1000):
        try:
            return f(*args, **kwargs)
        except ldap.BUSY:
            time.sleep(0.02)
    pytest.fail('Too many ldap.BUSY retries')


def base_search(inst, dn, attrs=None):
    return inst.search_s(dn, ldap.SCOPE_BASE, '(objectclass=*)',
                         attrs if attrs else ['dn'])


def load_in_cache(inst, *dns):
    for dn in dns:
        base_search(inst, dn)


def is_cached(inst, dn):
    """True if a base search finds the entry in the entry cache
    (i.e. the search does not add it in the cache).
    Note: the search loads the entry in the cache if it is not there.
    """
    win = ErrorLogWindow(inst)
    base_search(inst, dn)
    return not win.match(logpat(CACHE_ADD_LOG, dn))


def assert_cached(inst, dn):
    log.info(f'assert_cached({dn}')
    assert is_cached(inst, dn), f'{dn} was evicted from the entry cache'


def assert_not_exists(inst, dn):
    with pytest.raises(ldap.NO_SUCH_OBJECT):
        base_search(inst, dn)


def assert_rollback_log(win, template, dn):
    """Check a new rollback message (skipped if template is None)"""
    if template is not None:
        assert win.match(logpat(template, dn)), \
            f'No rollback message matching {logpat(template, dn)}'


def fake_members(count, prefix='fake'):
    return [f'uid={prefix}{i},{FAKE_MEMBERS_DN}' for i in range(count)]


_counter = [0]


def unique_name(prefix):
    _counter[0] += 1
    return f'{prefix}-{_counter[0]}'


def create_user(inst, request, good=True, parent=RBTEST_DN):
    """Create a user under ou=people,<parent>.
    A 'good' user can get memberOf, a 'bad' one makes memberOf fail.
    """
    name = unique_name('rb-user' if good else 'rb-bad')
    users = UserAccounts(inst, parent)
    user = users.create(properties={
        'uid': name,
        'cn': name,
        'sn': name,
        'uidNumber': str(10000 + _counter[0]),
        'gidNumber': str(10000 + _counter[0]),
        'homeDirectory': f'/home/{name}',
        UNIQUE_ATTR: name,
    })
    if good:
        if not user.present('objectClass', BAD_MEMBER_REMOVED_OC):
            user.add('objectClass', BAD_MEMBER_REMOVED_OC)
    else:
        if user.present('objectClass', BAD_MEMBER_REMOVED_OC):
            user.remove('objectClass', BAD_MEMBER_REMOVED_OC)
    cleanup(request, user)
    return user


def create_group(inst, request, members=None, basedn=GROUPS_DN):
    name = unique_name('rb-group')
    props = {'cn': name}
    if members:
        props['member'] = members
    group = Groups(inst, basedn, rdn=None).create(properties=props)
    cleanup(request, group)
    return group


def cleanup(request, obj, recursive=False):
    def fin():
        if DEBUGGING:
            return
        try:
            obj.delete(recursive=recursive)
        except ldap.NO_SUCH_OBJECT:
            pass
    request.addfinalizer(fin)


def trigger_postop_failure(env, group=None):
    """Make a betxn post-op plugin (memberOf) fail on a MODIFY of group"""
    group = group if group else env.fail_group
    with pytest.raises(MEMBEROF_ERROR):
        retry_if_busy(group.add_member, env.bad_user.dn)


def open_conn(inst):
    conn = ldap.initialize(f'ldap://{inst.host}:{inst.port}')
    conn.simple_bind_s(DN_DM, PW_DM)
    return conn


def reload_pinned(env):
    """Restart the server (empty cache) then load and check the pinned groups"""
    inst = env.inst
    inst.restart()
    win = ErrorLogWindow(inst)
    load_in_cache(inst, env.pin_mod.dn, env.pin_del.dn, env.pin_ren.dn)
    for group in (env.pin_mod, env.pin_del, env.pin_ren):
        assert win.match(logpat(PINNED_ADD_LOG, group.dn)), f'{group.dn} is not pinned'


def uniquemembers(inst, dn):
    return UniqueGroup(inst, dn).get_attr_vals_utf8_l('uniquemember')


def run_concurrently(env, worker, *args):
    """Run worker(conn, *args) in a thread while betxn post-op failures
    are triggered in the main thread.
    Returns the number of failures.
    """
    errors = []

    def target():
        conn = open_conn(env.inst)
        try:
            worker(conn, *args)
        except Exception as e:
            log.exception('Worker thread failed')
            errors.append(e)
        finally:
            conn.unbind_s()

    thread = threading.Thread(target=target)
    thread.start()
    nb_failures = 0
    while thread.is_alive() or nb_failures < MIN_FAILURES:
        trigger_postop_failure(env)
        nb_failures += 1
    thread.join()
    assert not errors
    log.info(f'{nb_failures} failing operations ran concurrently')
    return nb_failures


class RbEnv:
    pass


###########################################################################
# Fixtures
###########################################################################

@pytest.fixture(scope="module")
def rb_env(topology_st, request):
    """Prepare the test entries, the cache configuration and the plugins"""
    inst = topology_st.standalone
    env = RbEnv()
    env.inst = inst

    # Cache configuration
    if get_default_db_lib() == 'bdb':
        BDB_LDBMConfig(inst).set('nsslapd-cache-autosize', '0')
    else:
        LMDB_LDBMConfig(inst).set('nsslapd-cache-autosize', '0')
    be = Backends(inst).get(BACKEND_NAME)
    be.replace('nsslapd-cachememsize', ENTRY_CACHE_MEMSIZE)
    be.replace('nsslapd-cachesize', ENTRY_CACHE_SIZE)
    be.replace('nsslapd-dncachememsize', DN_CACHE_MEMSIZE)
    be.replace('nsslapd-cache-pinned-entries', str(NB_PINNED))
    be.replace('nsslapd-cache-debug-pattern', DEBUG_PATTERN)
    env.backend = be
    inst.config.set('nsslapd-errorlog-logbuffering', 'off')

    # Test subtrees
    ous = OrganizationalUnits(inst, DEFAULT_SUFFIX)
    env.rbtest = ous.create(properties={'ou': 'rbtest'})
    env.rbout = ous.create(properties={'ou': 'rbout'})
    for ou in ('people', 'groups', 'readers', 'aliases', 'dest'):
        OrganizationalUnits(inst, RBTEST_DN).create(properties={'ou': ou})
    OrganizationalUnits(inst, RBOUT_DN).create(properties={'ou': 'people'})

    # Members used to trigger memberOf failures
    env.bad_user = create_user(inst, request, good=False)
    env.good_user = create_user(inst, request, good=True)
    env.fail_group = create_group(inst, request)

    # Big groups (pinned in the entry cache once loaded from the database).
    # Created before enabling memberOf to keep their creation cheap.
    big = fake_members(BIG_GROUP_SIZE)
    env.pin_mod = UniqueGroups(inst, RBTEST_DN).create(
        properties={'cn': PIN_MOD_CN, 'uniquemember': big})
    env.pin_del = UniqueGroups(inst, RBTEST_DN).create(
        properties={'cn': PIN_DEL_CN, 'uniquemember': big})
    # In rbout (out of memberOf scope) with a bad member: moving it in
    # scope makes memberOf fail
    env.pin_ren = UniqueGroups(inst, RBOUT_DN, rdn=None).create(
        properties={'cn': PIN_REN_CN, 'uniquemember': big + [env.bad_user.dn]})

    # Readers used by the concurrency tests
    readers = OrganizationalUnits(inst, READERS_DN)
    env.readers = [readers.create(properties={'ou': f'reader-{i}'}).dn
                   for i in range(NB_READERS)]

    # memberOf: fails when a bad member is added to a group in scope
    memberof = MemberOfPlugin(inst)
    memberof.enable()
    memberof.replace_groupattr('member')
    memberof.add_groupattr('uniquemember')
    memberof.set_autoaddoc(MEMBEROF_AUTOADDOC)
    memberof.replace('memberOfEntryScope', RBTEST_DN)
    memberof.replace('memberOfDeferredUpdate', 'off')
    env.memberof = memberof

    # Attribute uniqueness: betxn pre-op failure
    attruniq = AttributeUniquenessPlugin(inst, dn='cn=rbtest uniqueness,cn=plugins,cn=config')
    attruniq.create(properties={'cn': 'rbtest uniqueness'})
    attruniq.add_unique_attribute(UNIQUE_ATTR)
    attruniq.add_unique_subtree(RBTEST_DN)
    attruniq.enable()
    env.attruniq = attruniq

    # Referential integrity: betxn post-op failure on DELETE
    referint = ReferentialIntegrityPlugin(inst)
    referint.enable()
    referint.replace('referint-update-delay', '0')
    referint.add('referint-membership-attr', REFERINT_ATTR)
    env.referint = referint

    inst.restart()

    def fin():
        if DEBUGGING:
            return
        inst.start()
        memberof.disable()
        referint.remove('referint-membership-attr', REFERINT_ATTR)
        referint.disable()
        attruniq.delete()
        inst.restart()
        for ou in (env.rbtest, env.rbout):
            ou.delete(recursive=True)

    request.addfinalizer(fin)
    return env


###########################################################################
# Task 1: skip useless reverts
###########################################################################

def test_rollback_skip_modify_uniqueness(rb_env, request):
    """MODIFY rejected by a betxn pre-op plugin does not walk the caches

    :id: 131f3a6e-1cd7-4554-8d15-36943f75a021
    :setup: Standalone instance with attribute uniqueness on employeeNumber
    :steps:
        1. Create two users and load them in the entry cache
        2. Modify user2 with the employeeNumber of user1
        3. Check the error log for the cache flush warning
        4. Check that both users are still in the entry cache
        5. Check that user2 is unchanged
    :expectedresults:
        1. Success
        2. Fails with CONSTRAINT_VIOLATION
        3. No flush warning (test plan 1.1 [new])
        4. Success
        5. Success
    """
    inst = rb_env.inst
    user1 = create_user(inst, request)
    user2 = create_user(inst, request)
    value2 = user2.get_attr_val_utf8(UNIQUE_ATTR)
    load_in_cache(inst, user1.dn, user2.dn)

    win = ErrorLogWindow(inst)
    with pytest.raises(UNIQUENESS_ERROR):
        user2.replace(UNIQUE_ATTR, user1.get_attr_val_utf8(UNIQUE_ATTR))
    assert not win.match(FLUSH_WARN_LOG)

    assert_cached(inst, user1.dn)
    assert_cached(inst, user2.dn)
    assert user2.get_attr_val_utf8(UNIQUE_ATTR) == value2


def test_rollback_add_uniqueness(rb_env, request):
    """ADD rejected by a betxn pre-op plugin leaves nothing in the caches

    :id: c3c59aae-c141-4d52-943b-f4b1c2b926ee
    :setup: Standalone instance with attribute uniqueness on employeeNumber
    :steps:
        1. Create a user
        2. Add a second user with the same employeeNumber
        3. Search the second user
        4. Add the second user with a unique employeeNumber
    :expectedresults:
        1. Success
        2. Fails with CONSTRAINT_VIOLATION (the tentative cache entry
           must be reverted, so a walk is expected: test plan 1.3 [both])
        3. Fails with NO_SUCH_OBJECT
        4. Success
    """
    inst = rb_env.inst
    user1 = create_user(inst, request)
    name = unique_name('rb-dup')
    users = UserAccounts(inst, RBTEST_DN)
    props = {
        'uid': name,
        'cn': name,
        'sn': name,
        'uidNumber': '20000',
        'gidNumber': '20000',
        'homeDirectory': f'/home/{name}',
        UNIQUE_ATTR: user1.get_attr_val_utf8(UNIQUE_ATTR),
    }
    dn = f'uid={name},{PEOPLE_DN}'

    win = ErrorLogWindow(inst)
    with pytest.raises(UNIQUENESS_ERROR):
        users.create(properties=dict(props))
    log.info(f'Cache walk on ADD rejected by uniqueness: {bool(win.match(FLUSH_WARN_LOG))}')
    assert_not_exists(inst, dn)

    props[UNIQUE_ATTR] = name
    user2 = users.create(properties=props)
    cleanup(request, user2)
    assert user2.exists()


def test_rollback_flag_reset(rb_env, request):
    """The "cache modified" flag is reset between operations on the same thread

    :id: a641f824-cb80-4085-8957-5267daf079fa
    :setup: Standalone instance with attribute uniqueness on employeeNumber
    :steps:
        1. Set nsslapd-threadnumber to 1 and restart (all operations
           then run on the same worker thread)
        2. Create two users
        3. Do a successful modify of user1
        4. Modify user2 with the employeeNumber of user1
        5. Check the error log for the cache flush warning
    :expectedresults:
        1. Success
        2. Success
        3. Success
        4. Fails with CONSTRAINT_VIOLATION
        5. No flush warning (test plan 1.5 [new])
    """
    inst = rb_env.inst
    orig = inst.config.get_attr_val_utf8('nsslapd-threadnumber')

    def fin():
        inst.config.replace('nsslapd-threadnumber', orig)
        inst.restart()

    request.addfinalizer(fin)
    inst.config.replace('nsslapd-threadnumber', '1')
    inst.restart()

    user1 = create_user(inst, request)
    user2 = create_user(inst, request)
    user1.replace('description', 'successful modify')

    win = ErrorLogWindow(inst)
    with pytest.raises(UNIQUENESS_ERROR):
        user2.replace(UNIQUE_ATTR, user1.get_attr_val_utf8(UNIQUE_ATTR))
    assert not win.match(FLUSH_WARN_LOG)


###########################################################################
# Task 2: ownership
###########################################################################

def test_rollback_modify(rb_env, request):
    """MODIFY failing in a betxn post-op plugin is rolled back in the cache

    :id: eb4fb9b0-82e2-4336-9984-c731c248e534
    :setup: Standalone instance with memberOf configured to fail on bad members
    :steps:
        1. Create a group with a good member and load it in the cache
        2. Add a bad member to the group
        3. Check the cache flush warning and the rollback messages
        4. Check the group members
    :expectedresults:
        1. Success
        2. Fails with OBJECT_CLASS_VIOLATION
        3. The flush warning is logged; the group is evicted (test plan 2.1)
        4. Only the good member is present (test plan 2.1 [both])
    """
    inst = rb_env.inst
    good = create_user(inst, request)
    group = create_group(inst, request, members=[good.dn])
    load_in_cache(inst, group.dn)

    win = ErrorLogWindow(inst)
    trigger_postop_failure(rb_env, group)
    assert win.match(FLUSH_WARN_LOG)
    assert_rollback_log(win, ROLLBACK_EVICT_LOG, group.dn)

    assert group.is_member(good.dn)
    assert not group.is_member(rb_env.bad_user.dn)
    assert len(group.get_attr_vals_utf8_l('member')) == 1


def test_rollback_nested_operations(rb_env, request):
    """Changes done by nested (plugin) operations are rolled back too

    :id: 8d542929-0ccf-4da8-bfb8-2bf5b4c04c89
    :setup: Standalone instance with memberOf configured to fail on bad members
    :steps:
        1. Create an empty group and a good user, load them in the cache
        2. In one MODIFY: add the good user (memberOf succeeds, the user
           entry is updated by a nested operation), then the bad user
        3. Check the rollback messages
        4. Check the good user memberOf attribute
        5. Check the group members
    :expectedresults:
        1. Success
        2. Fails with OBJECT_CLASS_VIOLATION
        3. The good user (changed by the nested operation) is evicted
        4. The good user is not member of the group (test plan 2.2 [both])
        5. The group has no member
    """
    inst = rb_env.inst
    good = create_user(inst, request)
    group = create_group(inst, request)
    load_in_cache(inst, group.dn, good.dn)

    win = ErrorLogWindow(inst)
    with pytest.raises(MEMBEROF_ERROR):
        retry_if_busy(group.apply_mods, [(ldap.MOD_ADD, 'member', good.dn),
                                         (ldap.MOD_ADD, 'member', rb_env.bad_user.dn)])
    assert_rollback_log(win, ROLLBACK_EVICT_LOG, good.dn)

    assert group.dn.lower() not in good.get_attr_vals_utf8_l('memberOf')
    assert not group.get_attr_vals_utf8_l('member')


def test_rollback_add(rb_env, request):
    """ADD failing in a betxn post-op plugin is rolled back in both caches

    :id: 1f77866a-dcd0-4a49-8c71-106b44cc603a
    :setup: Standalone instance with memberOf configured to fail on bad members
    :steps:
        1. Get the numSubordinates of the groups container
        2. Add a group having the bad user as member
        3. Search the group
        4. Check the numSubordinates of the groups container
        5. Add the group with a good member
    :expectedresults:
        1. Success
        2. Fails with OBJECT_CLASS_VIOLATION
        3. Fails with NO_SUCH_OBJECT (test plan 2.3 [both])
        4. Unchanged
        5. Success
    """
    inst = rb_env.inst
    good = create_user(inst, request)
    groups_ou = OrganizationalUnits(inst, RBTEST_DN).get('groups')
    nbsub = groups_ou.get_attr_val_int('numSubordinates')
    name = unique_name('rb-addgroup')
    dn = f'cn={name},{GROUPS_DN}'
    groups = Groups(inst, GROUPS_DN, rdn=None)

    with pytest.raises(MEMBEROF_ERROR):
        groups.create(properties={'cn': name, 'member': [rb_env.bad_user.dn]})
    assert_not_exists(inst, dn)
    assert groups_ou.get_attr_val_int('numSubordinates') == nbsub

    group = groups.create(properties={'cn': name, 'member': [good.dn]})
    cleanup(request, group)
    assert group.is_member(good.dn)


def test_rollback_modrdn(rb_env, request):
    """MODRDN failing in a betxn post-op plugin is rolled back in both caches

    :id: dcd591b8-0f26-4bbc-8b6d-5fe6894d73a3
    :setup: Standalone instance with memberOf configured to fail on bad members
    :steps:
        1. Create a group with a bad member out of memberOf scope (ou=rbout)
        2. Load the group and both parents in the cache
        3. Move the group in memberOf scope (newsuperior ou=groups,ou=rbtest)
        4. Search the group with its old and new DN
        5. Check numSubordinates of both parents
        6. One level searches under both parents
    :expectedresults:
        1. Success
        2. Success
        3. Fails with OBJECT_CLASS_VIOLATION
        4. Old DN found, new DN gives NO_SUCH_OBJECT (test plan 2.4 [both])
        5. Unchanged
        6. The group is only found under its old parent
    """
    inst = rb_env.inst
    group = create_group(inst, request, members=[rb_env.bad_user.dn], basedn=RBOUT_DN)
    cn = group.get_attr_val_utf8('cn')
    old_dn = group.dn
    new_dn = f'cn={cn},{GROUPS_DN}'
    rbout = rb_env.rbout
    groups_ou = OrganizationalUnits(inst, RBTEST_DN).get('groups')
    nbsub_out = rbout.get_attr_val_int('numSubordinates')
    nbsub_groups = groups_ou.get_attr_val_int('numSubordinates')
    load_in_cache(inst, old_dn, RBOUT_DN, GROUPS_DN)

    with pytest.raises(MEMBEROF_ERROR):
        retry_if_busy(group.rename, f'cn={cn}', newsuperior=GROUPS_DN)

    base_search(inst, old_dn)
    assert_not_exists(inst, new_dn)
    assert rbout.get_attr_val_int('numSubordinates') == nbsub_out
    assert groups_ou.get_attr_val_int('numSubordinates') == nbsub_groups
    assert inst.search_s(RBOUT_DN, ldap.SCOPE_ONELEVEL, f'(cn={cn})', ['dn'])
    assert not inst.search_s(GROUPS_DN, ldap.SCOPE_ONELEVEL, f'(cn={cn})', ['dn'])


def test_rollback_subtree_modrdn(rb_env, request):
    """Subtree MODRDN failing in a betxn post-op plugin is rolled back
    in the DN cache

    :id: b46c78a0-1aee-416a-b2ba-cdafa02d7d9c
    :setup: Standalone instance with memberOf configured to fail on bad members
    :steps:
        1. Create a group with a bad member out of memberOf scope, with
           three child entries
        2. Load the group and its children in the cache
        3. Move the group in memberOf scope
        4. Search the children with their old and new DNs
        5. One level search under the group old DN
    :expectedresults:
        1. Success
        2. Success
        3. Fails with OBJECT_CLASS_VIOLATION
        4. Old DNs found, new DNs give NO_SUCH_OBJECT (test plan 2.5 [both])
        5. The three children are returned
    """
    inst = rb_env.inst
    group = create_group(inst, request, members=[rb_env.bad_user.dn], basedn=RBOUT_DN)
    cn = group.get_attr_val_utf8('cn')
    children = []
    for i in range(3):
        child = OrganizationalUnits(inst, group.dn).create(properties={'ou': f'child{i}'})
        cleanup(request, child)
        children.append(child.dn)
    load_in_cache(inst, group.dn, *children)

    with pytest.raises(MEMBEROF_ERROR):
        retry_if_busy(group.rename, f'cn={cn}', newsuperior=GROUPS_DN)

    new_group_dn = f'cn={cn},{GROUPS_DN}'
    for i, dn in enumerate(children):
        base_search(inst, dn)
        assert_not_exists(inst, f'ou=child{i},{new_group_dn}')
    assert len(inst.search_s(group.dn, ldap.SCOPE_ONELEVEL, '(objectclass=*)', ['dn'])) == 3


def test_rollback_delete(rb_env, request):
    """DELETE failing in a betxn post-op plugin is rolled back in the cache

    :id: f7bb54e3-01e0-4db3-9a55-e979abe64318
    :setup: Standalone instance with referint configured on aliasedObjectName
    :steps:
        1. Create a user and an alias entry referencing it, load them in the cache
        2. Delete the user (referint cannot remove the MUST aliasedObjectName)
        3. Search the user
        4. Check the numSubordinates of the people container
        5. Check the alias entry
    :expectedresults:
        1. Success
        2. Fails with OBJECT_CLASS_VIOLATION
        3. Found with all its attributes (test plan 2.6 [both])
        4. Unchanged
        5. Still references the user
    """
    inst = rb_env.inst
    user = create_user(inst, request)
    alias = create_alias(inst, user.dn)
    cleanup(request, alias)     # Registered last so it is deleted before the user
    people_ou = OrganizationalUnits(inst, RBTEST_DN).get('people')
    nbsub = people_ou.get_attr_val_int('numSubordinates')
    sn = user.get_attr_val_utf8('sn')
    load_in_cache(inst, user.dn, alias.dn)

    with pytest.raises(REFERINT_ERROR):
        retry_if_busy(user.delete)

    assert user.exists()
    assert user.get_attr_val_utf8('sn') == sn
    assert people_ou.get_attr_val_int('numSubordinates') == nbsub
    assert alias.get_attr_val_utf8_l(REFERINT_ATTR) == user.dn.lower()


def test_rollback_keep_read_entries(rb_env, request):
    """Entries already in the cache and only read by the failing operation
    are not evicted

    :id: 74ec4bc7-c62a-4a4d-b5db-6e73ed59a840
    :setup: Standalone instance with memberOf configured to fail on bad members
    :steps:
        1. Load the bad user, the good user and an unrelated group in the cache
        2. Make memberOf fail (the bad user is read by the nested modify
           that fails before changing the cache)
        3. Check the cache remove messages
        4. Check that the entries are still in the cache
    :expectedresults:
        1. Success
        2. Fails with OBJECT_CLASS_VIOLATION
        3. No remove message for these entries (test plan 2.7 [both])
        4. Success
    """
    inst = rb_env.inst
    other = create_group(inst, request)
    dns = [rb_env.bad_user.dn, rb_env.good_user.dn, other.dn]
    load_in_cache(inst, *dns)

    win = ErrorLogWindow(inst)
    trigger_postop_failure(rb_env)
    for dn in dns:
        assert not win.match(logpat(CACHE_REMOVE_LOG, dn))
        assert not win.match(logpat(ROLLBACK_EVICT_LOG, dn))
        assert_cached(inst, dn)


def test_rollback_concurrent_readers(rb_env):
    """Entries loaded by other threads during the failing operation
    are not evicted

    :id: 71f6ac3b-3151-40bc-856d-eb29d91cd950
    :setup: Standalone instance with memberOf configured to fail on bad members
    :steps:
        1. Restart the server (empty cache)
        2. In a thread, do a base search on each reader entry (each search
           loads the entry in the cache) while the main thread loops on
           operations failing in memberOf
        3. Check the cache remove messages for the reader entries
    :expectedresults:
        1. Success
        2. Success
        3. No reader entry was removed from the cache (test plan 2.8 [new]:
           with the old code some of them are evicted; the result depends
           on timing)
    """
    inst = rb_env.inst
    inst.restart()

    def reader(conn, dns):
        for dn in dns:
            conn.search_s(dn, ldap.SCOPE_BASE, '(objectclass=*)', ['dn'])

    win = ErrorLogWindow(inst)
    run_concurrently(rb_env, reader, rb_env.readers)
    readers_regex = r'.*' + re.escape(ndn(READERS_DN))
    removed = win.match(logpat(CACHE_REMOVE_LOG, dn_regex=readers_regex))
    assert not removed, f'{len(removed)} reader entries were evicted'
    # All readers were loaded during the test
    assert len(win.match(logpat(CACHE_ADD_LOG, dn_regex=readers_regex))) >= NB_READERS


def test_rollback_concurrent_writers(rb_env):
    """Entries modified by other threads during the failing operation
    are not evicted and keep their new values

    :id: 7445b90d-d9e5-4b4f-afb3-16054e86421d
    :setup: Standalone instance with memberOf configured to fail on bad members
    :steps:
        1. Load the reader entries in the cache
        2. In a thread, modify each reader entry while the main thread loops
           on operations failing in memberOf
        3. Check the cache remove messages for the reader entries
        4. Check the reader entries values
    :expectedresults:
        1. Success
        2. Success
        3. No reader entry was removed from the cache (test plan 2.9 [new])
        4. All reader entries have the new value
    """
    inst = rb_env.inst
    load_in_cache(inst, *rb_env.readers)
    value = unique_name('rb-written')

    def writer(conn, dns):
        for dn in dns:
            retry_if_busy(conn.modify_s, dn, [(ldap.MOD_REPLACE, 'description', value.encode())])

    win = ErrorLogWindow(inst)
    run_concurrently(rb_env, writer, rb_env.readers)
    readers_regex = r'.*' + re.escape(ndn(READERS_DN))
    removed = win.match(logpat(CACHE_REMOVE_LOG, dn_regex=readers_regex))
    assert not removed, f'{len(removed)} reader entries were evicted'
    entries = inst.search_s(READERS_DN, ldap.SCOPE_ONELEVEL, '(objectclass=*)', ['description'])
    assert len(entries) == NB_READERS
    for entry in entries:
        assert entry.getValue('description') == value.encode()


def test_rollback_keep_entries_loaded_without_update(rb_env, request):
    """Entries loaded by searches and by a task are not evicted by a
    later rollback

    :id: feb15dd7-1edb-4e6e-b0c8-64faf16d4509
    :setup: Standalone instance with memberOf configured to fail on bad members
    :steps:
        1. Restart the server (empty cache)
        2. Load some entries with searches
        3. Run a memberOf fixup task on ou=people,ou=rbtest
        4. Make memberOf fail
        5. Check that the entries are still in the cache
    :expectedresults:
        1. Success
        2. Success
        3. Success
        4. Fails with OBJECT_CLASS_VIOLATION
        5. Success (test plan 2.12 [both])
    """
    inst = rb_env.inst
    good = create_user(inst, request)
    group = create_group(inst, request, members=[good.dn])
    inst.restart()
    dns = [good.dn, group.dn, rb_env.good_user.dn]
    load_in_cache(inst, *dns)
    task = rb_env.memberof.fixup(PEOPLE_DN)
    task.wait()
    assert task.get_exit_code() == 0

    trigger_postop_failure(rb_env)
    for dn in dns:
        assert_cached(inst, dn)


@pytest.mark.xfail(reason='revert_cache() only reverts the caches of the backend '
                          'of the parent operation', strict=False)
def test_rollback_nested_other_backend(rb_env, request):
    """A nested update done in another backend is rolled back

    :id: ec8576f2-b648-4d85-a8f9-0c475071a11f
    :setup: Standalone instance with memberOf configured to fail on bad
            members, and a second backend
    :steps:
        1. Create a second backend with a good user, enable
           memberOfAllBackends and add the backend in the memberOf scope
        2. Load the user in the cache
        3. In one MODIFY of a group: add the user of the second backend,
           then the bad user
        4. Check the memberOf attribute of the second backend user
    :expectedresults:
        1. Success
        2. Success
        3. Fails with OBJECT_CLASS_VIOLATION
        4. The user is not member of the group (test plan 2.11: documents
           the current behavior, expected to fail)
    """
    inst = rb_env.inst
    memberof = rb_env.memberof
    be2 = Backends(inst).create(properties={'cn': BACKEND2_NAME, 'nsslapd-suffix': SUFFIX2})
    be2.replace('nsslapd-cache-debug-pattern', f'.*{SUFFIX2}$')
    Domain(inst, SUFFIX2).create(properties={'dc': SUFFIX2.split(',')[0][3:]})
    memberof.enable_allbackends()
    memberof.add_entryscope(SUFFIX2)
    inst.restart()

    def fin():
        if DEBUGGING:
            return
        memberof.remove_entryscope(SUFFIX2)
        memberof.disable_allbackends()
        be2.delete()
        inst.restart()

    request.addfinalizer(fin)

    OrganizationalUnits(inst, SUFFIX2).create(properties={'ou': 'people'})
    user2 = create_user(inst, request, parent=SUFFIX2)
    group = create_group(inst, request)
    load_in_cache(inst, user2.dn)

    with pytest.raises(MEMBEROF_ERROR):
        retry_if_busy(group.apply_mods, [(ldap.MOD_ADD, 'member', user2.dn),
                                         (ldap.MOD_ADD, 'member', rb_env.bad_user.dn)])
    assert group.dn.lower() not in UserAccount(inst, user2.dn).get_attr_vals_utf8_l('memberOf')


###########################################################################
# Task 3: reverting the pinned entries
###########################################################################

def test_rollback_pinned_modify(rb_env):
    """A pinned entry replaced by the failing operation is reverted,
    not evicted

    :id: 6c2d73b4-1fef-499e-b2bc-2b58d7522faf
    :setup: Standalone instance with big groups pinned in the entry cache
    :steps:
        1. Restart and load the pinned groups
        2. Add the bad user to the pinned group
        3. Check the rollback messages
        4. Search the pinned group
        5. Check the pinned group members
    :expectedresults:
        1. The groups are pinned
        2. Fails with OBJECT_CLASS_VIOLATION
        3. The group is reverted (test plan 3.1 [new])
        4. The group is still in the entry cache (not reloaded)
        5. The members are unchanged
    """
    env = rb_env
    inst = env.inst
    reload_pinned(env)

    win = ErrorLogWindow(inst)
    with pytest.raises(MEMBEROF_ERROR):
        retry_if_busy(env.pin_mod.add, 'uniquemember', env.bad_user.dn)
    assert_rollback_log(win, ROLLBACK_REVERT_LOG, env.pin_mod.dn)

    assert_cached(inst, env.pin_mod.dn)
    members = uniquemembers(inst, env.pin_mod.dn)
    assert len(members) == BIG_GROUP_SIZE
    assert env.bad_user.dn.lower() not in members


def test_rollback_pinned_and_normal_nested(rb_env, request):
    """A pinned entry and a normal entry replaced by nested operations:
    the pinned one is reverted, the normal one is evicted

    :id: 2bb4a969-0805-4ca3-ad31-1b8d1fad8ea8
    :setup: Standalone instance with big groups pinned in the entry cache
    :steps:
        1. Restart and load the pinned groups, a small group and a good user
        2. In one MODIFY of the small group: add the pinned group (memberOf
           updates it in a nested operation), the good user (same), then
           the bad user
        3. Check the rollback messages
        4. Search the pinned group
        5. Check the memberOf attribute of the pinned group and of the user
    :expectedresults:
        1. The groups are pinned
        2. Fails with OBJECT_CLASS_VIOLATION
        3. Pinned group reverted, good user evicted (test plan 3.2/3.6 [new])
        4. The pinned group is still in the entry cache (not reloaded)
        5. None of them is member of the small group
    """
    env = rb_env
    inst = env.inst
    good = create_user(inst, request)
    group = create_group(inst, request)
    reload_pinned(env)
    load_in_cache(inst, group.dn, good.dn)

    win = ErrorLogWindow(inst)
    with pytest.raises(MEMBEROF_ERROR):
        retry_if_busy(group.apply_mods, [(ldap.MOD_ADD, 'member', env.pin_mod.dn),
                                         (ldap.MOD_ADD, 'member', good.dn),
                                         (ldap.MOD_ADD, 'member', env.bad_user.dn)])
    assert_rollback_log(win, ROLLBACK_REVERT_LOG, env.pin_mod.dn)
    assert_rollback_log(win, ROLLBACK_EVICT_LOG, good.dn)

    assert_cached(inst, env.pin_mod.dn)
    assert group.dn.lower() not in env.pin_mod.get_attr_vals_utf8_l('memberOf')
    assert group.dn.lower() not in good.get_attr_vals_utf8_l('memberOf')


def test_rollback_pinned_modified_twice(rb_env):
    """A pinned entry replaced twice by the failing operation (parent and
    nested operation) gets its original version back

    :id: 877c9bf6-8447-4241-a3a1-b3e67aab4d11
    :setup: Standalone instance with big groups pinned in the entry cache
    :steps:
        1. Restart and load the pinned groups
        2. In one MODIFY of the pinned group: add the group itself as
           uniquemember (memberOf then updates the group again in a nested
           operation), then the bad user
        3. Search the pinned group
        4. Check the pinned group members and memberOf
    :expectedresults:
        1. The groups are pinned
        2. Fails
        3. The group is still in the entry cache (test plan 3.2 [new])
        4. The original version is back (no new uniquemember, no memberOf)
    """
    env = rb_env
    inst = env.inst
    dn = env.pin_mod.dn
    reload_pinned(env)

    with pytest.raises(ldap.LDAPError):
        retry_if_busy(env.pin_mod.apply_mods, [(ldap.MOD_ADD, 'uniquemember', dn),
                                               (ldap.MOD_ADD, 'uniquemember', env.bad_user.dn)])

    assert_cached(inst, dn)
    members = uniquemembers(inst, dn)
    assert len(members) == BIG_GROUP_SIZE
    assert dn.lower() not in members
    assert dn.lower() not in env.pin_mod.get_attr_vals_utf8_l('memberOf')


def test_rollback_pinned_concurrent(rb_env, request):
    """Concurrent successful and failing updates of a pinned entry

    :id: c00ce7f9-9da2-458f-a696-e546c194e10b
    :setup: Standalone instance with big groups pinned in the entry cache
    :steps:
        1. Restart and load the pinned groups
        2. In a thread, add new uniquemember values one by one to the
           pinned group while the main thread loops on adding the bad user
           to the same group (failing in memberOf)
        3. Check the pinned group members
        4. Check the server is still running
    :expectedresults:
        1. The groups are pinned
        2. Success
        3. All values added by the thread are present, the bad user is
           not (test plan 3.3 [both])
        4. Success
    """
    env = rb_env
    inst = env.inst
    added = fake_members(MIN_FAILURES, prefix='conc')
    reload_pinned(env)

    def fin():
        # Restore the group even when DEBUGGING: the next tests need it
        for value in added:
            try:
                env.pin_mod.remove('uniquemember', value)
            except ldap.NO_SUCH_ATTRIBUTE:
                pass

    request.addfinalizer(fin)

    def writer(conn, dn, values):
        for value in values:
            retry_if_busy(conn.modify_s, dn, [(ldap.MOD_ADD, 'uniquemember', value.encode())])

    errors = []

    def target():
        conn = open_conn(inst)
        try:
            writer(conn, env.pin_mod.dn, added)
        except Exception as e:
            log.exception('Writer thread failed')
            errors.append(e)
        finally:
            conn.unbind_s()

    thread = threading.Thread(target=target)
    thread.start()
    nb = 0
    while thread.is_alive() or nb < MIN_FAILURES:
        trigger_postop_failure(env, env.pin_mod)
        nb += 1
    thread.join()
    assert not errors

    members = uniquemembers(inst, env.pin_mod.dn)
    assert len(members) == BIG_GROUP_SIZE + len(added)
    for value in added:
        assert value.lower() in members
    assert env.bad_user.dn.lower() not in members
    assert inst.status()


def test_rollback_pinned_success_path(rb_env):
    """Successful updates of a pinned entry release the old versions

    :id: 9a16cdc7-c51d-42fd-a4ad-912f13b5a96d
    :setup: Standalone instance with big groups pinned in the entry cache
    :steps:
        1. Restart and load the pinned groups, get the entry cache counters
        2. Add then remove a uniquemember value of the pinned group,
           many times
        3. Get the entry cache counters
        4. Search the pinned group
        5. Check the pinned group members
    :expectedresults:
        1. The groups are pinned
        2. Success
        3. currententrycachecount is unchanged (test plan 3.4 [both];
           run with ASAN to detect leaked entries)
        4. The group is still in the entry cache
        5. The members are unchanged
    """
    env = rb_env
    inst = env.inst
    reload_pinned(env)
    monitor = env.backend.get_monitor()
    count = monitor.get_attr_val_int('currententrycachecount')

    value = f'uid=success-path,{FAKE_MEMBERS_DN}'
    for _ in range(NB_SUCCESSFUL_MODS):
        env.pin_mod.add('uniquemember', value)
        env.pin_mod.remove('uniquemember', value)

    assert monitor.get_attr_val_int('currententrycachecount') == count
    assert_cached(inst, env.pin_mod.dn)
    assert len(uniquemembers(inst, env.pin_mod.dn)) == BIG_GROUP_SIZE


def test_rollback_pinned_modrdn(rb_env):
    """A pinned entry renamed by a failing MODRDN is reverted

    :id: 272b7230-cc03-45fe-a125-dce4a2550919
    :setup: Standalone instance with big groups pinned in the entry cache
    :steps:
        1. Restart and load the pinned groups
        2. Move the pinned group of ou=rbout (it has the bad user as
           member) in memberOf scope
        3. Check the rollback messages
        4. Search the group with its old and new DN
    :expectedresults:
        1. The groups are pinned
        2. Fails with OBJECT_CLASS_VIOLATION
        3. The group is reverted (test plan 3.5 [new])
        4. Old DN still in the entry cache, new DN gives NO_SUCH_OBJECT
    """
    env = rb_env
    inst = env.inst
    reload_pinned(env)

    win = ErrorLogWindow(inst)
    with pytest.raises(MEMBEROF_ERROR):
        retry_if_busy(env.pin_ren.rename, f'cn={PIN_REN_CN}', newsuperior=GROUPS_DN)
    assert_rollback_log(win, ROLLBACK_REVERT_LOG, env.pin_ren.dn)

    assert_cached(inst, env.pin_ren.dn)
    assert_not_exists(inst, f'cn={PIN_REN_CN},{GROUPS_DN}')
    assert len(uniquemembers(inst, env.pin_ren.dn)) == BIG_GROUP_SIZE + 1


def test_rollback_pinned_delete(rb_env, request):
    """A pinned entry whose DELETE fails stays pinned in the cache

    :id: 2f25a3f3-f5a5-44d4-87f0-a619652c5942
    :setup: Standalone instance with big groups pinned in the entry cache
    :steps:
        1. Create an alias entry referencing the pinned group
        2. Restart and load the pinned groups
        3. Delete the pinned group (referint fails)
        4. Search the pinned group
        5. Check the pinned group members
    :expectedresults:
        1. Success
        2. The groups are pinned
        3. Fails with OBJECT_CLASS_VIOLATION
        4. The group is still in the entry cache (test plan 3.5 [both])
        5. The members are unchanged
    """
    env = rb_env
    inst = env.inst
    alias = create_alias(inst, env.pin_del.dn)
    cleanup(request, alias)
    reload_pinned(env)

    with pytest.raises(REFERINT_ERROR):
        retry_if_busy(env.pin_del.delete)

    assert_cached(inst, env.pin_del.dn)
    assert len(uniquemembers(inst, env.pin_del.dn)) == BIG_GROUP_SIZE


if __name__ == '__main__':
    # Run isolated
    # -s for DEBUG mode
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main("-s %s" % CURRENT_FILE)
