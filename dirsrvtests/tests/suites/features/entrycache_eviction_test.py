# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2025 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
import os
import logging
import pytest
from contextlib import suppress
from lib389.backend import Backends
from lib389.cli_base import FakeArgs
from lib389.cli_ctl.dbgen import dbgen_create_groups
from lib389.dirsrv_log import DirsrvErrorLog
from lib389.tasks import ImportTask
from lib389.topologies import topology_st


pytestmark = pytest.mark.tier1

DEBUGGING = os.getenv("DEBUGGING", default=False)
logging.getLogger(__name__).setLevel(logging.DEBUG)
log = logging.getLogger(__name__)

BECACHEATTRS= [ 'nsslapd-cache-weight-threshold', 'nsslapd-cache-debug-pattern', 
                'nsslapd-cachesize', 'nsslapd-cachememsize' ]

@pytest.fixture(scope="function")
def prepare_be(topology_st, request):

    inst = topology_st.standalone
    ldif_file = inst.get_ldif_dir() + '/30ku.ldif'
    bename = 'entrycache_test'
    suffix = 'dc=entrycache_test,dc=example,dc=com'

    # Remove the backend if it exists
    bes = Backends(inst)
    with suppress(ldap.NO_SUCH_OBJECT):
        be1 = bes.get(bename)
        be1.delete()

    # Creates the backend.
    be1 = bes.create(properties={ 'cn': 'cn={bename}', 'nsslapd-suffix': suffix, })

    # Prepare finalizer
    def fin():
        be1.delete()
        if os.path.exists(ldif_file):
            os.remove(ldif_file)

    if not DEBUGGING:
        request.addfinalizer(fin)

    # Generates ldif file with a few clarge groups
    args = FakeArgs()
    args.NAME = 'myGroup'
    args.parent = f'ou=groups,{suffix}'
    args.suffix = DEFAULT_SUFFIX
    args.number = 5
    args.num_members = 6000
    args.create_members = True
    args.member_attr = 'uniquemember'
    args.member_parent = f'ou=people,{suffix}'
    args.ldif_file = ldif_file
    dbgen_create_groups(standalone, log, args)
    assert os.path.exists(ldif_file)

    # Import the ldif
    import_task = ImportTask(inst)
    import_task.import_suffix_from_ldif(ldiffile=ldif_file,
                                        suffix=suffix)
    import_task.wait()
    assert import_task.get_exit_code() == 0

    # Set entry cache large enough to hold all the large groups
    # and some entries.
    be1.replace('nsslapd-cachememsize',  '8000000' )
    be1.replace('nsslapd-cachesize',  '100' )
    # Set debugging trace specific for this test
    be1.replace('nsslapd-cache-debug-pattern',  f'cn=cn=.*,ou=groups,{suffix}' )

    return (bename, suffix)

    
def test_entry_cache_eviction(topology_st, prepare_be):
    """Test that large groups are not evicted

            :id: 550b995e-1c76-11f0-93ed-482ae39447e5
            :setup: Standalone instance
            :steps:
                 1. Create DS instance and prepare a test backend
                 2. Search all entries
                 3. Check error log that the group are added in cache but not removed
                 3. Change the eviction threshold so that groups are not preserved.
                 2. Search all entries
                 3. Check error log that the group are removed except the last one
            :expectedresults:
                 1. Success
                 2. Success
                 3. Success
                 4. Success
            """

    inst = topology_st.standalone
    bename, suffix = prepare_be

    # Search all entries 
    inst.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, '(objectclass=top)', ['dn'], escapehatch='i am sure')

    # Check error logs
    errlog = DirsrvErrorLog(inst)
    results = errlog.match('entrycache_.*_int')
    # Should have entrycache_add_int for each group and no entrycache_delete_int
    assert len(results) == 5
    for res in results:
        assert 'entrycache_delete_int' not in res
        assert 'entrycache_add_int' in res

    be1.replace('nsslapd-cache-weight-threshold', '1000000')
    # Search all entries 
    inst.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, '(objectclass=top)', ['dn'], escapehatch='i am sure')
    # Should log new messages:
    #  groups 2,3,4,5 removed from cache group 2 added, group 1 removed, group 3 added, group 2 removed,
    #  group 4 added, group 3 removed, group 5 added, group 4 removed
    #  a total of 17 messages (5 from previous search and 12 from this one)

    # Check error logs
    errlog = DirsrvErrorLog(inst)
    results = errlog.match('entrycache_.*_int')
    # Should have entrycache_add_int and entrycache_delete_int 
    #  for each group and no entrycache_delete_int
    assert len(results) == 17
    assert 'entrycache_delete_int' in "\n".join(results)
    for res in results:
        assert 'entrycache_delete_int' in res or 'entrycache_add_int' in res


if __name__ == "__main__":
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main("-s -v %s" % CURRENT_FILE)

