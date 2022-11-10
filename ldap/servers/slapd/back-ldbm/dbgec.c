/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2023 Red Hat, Inc.
 * All rights reserved.
 *
 * License: GPL (version 3 or any later version).
 * See LICENSE for details.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#define MAX_LOGSLOTS (1<<13)

#define ABORT() {   slapi_log_err(SLAPI_LOG_ERR, (char*)__func__, "%s[%d]: ABORT\n", __FILE__, __LINE__); \
                    slapi_log_backtrace(SLAPI_LOG_ERR); \
                    *(char*)23=1; }

struct {
    int lastslot;
    struct {
        void *addr;
        char dn[150];
    } slots[MAX_LOGSLOTS];
} *dbgec_log;

static int dbgec_debug = 0;

void dbgec_log_init()
{
    if (dbgec_log) {
        return;
    }
    /* Find log path */
    Slapi_PBlock *pb = slapi_search_internal(SLAPD_CONFIG_DN, LDAP_SCOPE_BASE, "objectclass=*", NULL, NULL, 0);
    Slapi_Entry **entries;
    Slapi_Attr *attr;
    Slapi_Value *value;
    int rt;

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rt);
    if (rt != LDAP_SUCCESS) {
        slapi_log_err(SLAPI_LOG_ERR, "_init_debuglog", "search operation failed; LDAP error - %d\n", rt);
        ABORT();
    }
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
    if (entries == NULL || entries[0] == NULL) {
        slapi_log_err(SLAPI_LOG_ERR, "_init_debuglog", "failed to get %s entry.\n", SLAPD_CONFIG_DN);
        ABORT();
    }
    const char *logpath = NULL;
    /* get port */
    rt = slapi_entry_attr_find(entries[0], CONFIG_ERRORLOG_ATTRIBUTE, &attr);
    if (rt == LDAP_SUCCESS) {
        slapi_attr_first_value(attr, &value);
        if (value != NULL) {
            logpath = slapi_value_get_string(value);
        }
    }
    if (!logpath) {
        slapi_log_err(SLAPI_LOG_ERR, "_init_debuglog", "failed to get %s attribute in config entry.\n", CONFIG_ERRORLOG_ATTRIBUTE);
        ABORT();
    }
    char *pt = strrchr(logpath,'/');
    if (!pt) {
        slapi_log_err(SLAPI_LOG_ERR, "_init_debuglog", "invalid error log path %s\n", logpath);
        ABORT();
    }

    char *path = malloc(pt-logpath+50);
    strncpy(path, logpath, pt-logpath);
    strcpy(path+(pt-logpath), "/debug-not-rotationinfo.bin");  /* Should have rotationinfo so that conftest.py ignore it */
    /* Create a log file full of \0 */
    int fd = open(path, O_RDWR|O_CREAT|O_TRUNC, 0640);
    if (fd<0) {
        slapi_log_err(SLAPI_LOG_ERR, "_init_debuglog", "errno: %d %s\n", errno, strerror(errno));
        slapi_log_err(SLAPI_LOG_ERR, "_init_debuglog", "Unable to create debug log file %s.\n", path);
        ABORT();
    }
    size_t flen = sizeof *dbgec_log;
    if (ftruncate(fd, flen)) {
        slapi_log_err(SLAPI_LOG_ERR, "_init_debuglog", "errno: %d %s\n", errno, strerror(errno));
        slapi_log_err(SLAPI_LOG_ERR, "_init_debuglog", "Unable to set file %s size to %ld.\n", path, flen);
        ABORT();
    }
    dbgec_log = mmap(NULL, flen, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (!dbgec_log || dbgec_log == MAP_FAILED) {
        slapi_log_err(SLAPI_LOG_ERR, "_init_debuglog", "errno: %d %s\n", errno, strerror(errno));
        slapi_log_err(SLAPI_LOG_ERR, "_init_debuglog", "Failed to mmap debug log file %s.\n", path);
        ABORT();
    }
    close(fd);
    slapi_ch_free_string(&path);
    slapi_pblock_destroy(pb);
}

static void inline dbgec_log_add(void *addr, const char *dn)
{
    if (dbgec_log) {
        dbgec_log->slots[dbgec_log->lastslot].addr = addr;
        /* As the mmaped file is zeroed when ftruncated, the dbgec_log->slots[x].dn is NULL terminated */
        strncpy(dbgec_log->slots[dbgec_log->lastslot].dn, dn, (sizeof dbgec_log->slots->dn)-1);
        dbgec_log->lastslot = (dbgec_log->lastslot+1) &(MAX_LOGSLOTS-1);
    }
}

void dbgec_log_lookup(void *addr)
{
    if (dbgec_log) {
        for (size_t i=0; i<MAX_LOGSLOTS && dbgec_log->slots[i].addr; i++) {
		    if (dbgec_log->slots[i].addr == addr) {
                slapi_log_err(SLAPI_LOG_ERR, "dbgec_log_lookup", "Found address %p associated with dn %s\n", addr, dbgec_log->slots[i].dn);
            }
        }
    }
}

void dbgec_init()
{
    static int initted = 0;
    if (!initted) {
        initted++;
        /* Cannot use getenv("PYTEST_CURRENT_TEST") to determine that we are running in pytest
         * because systemd reset the environment
        char *pt = getenv("PYTEST_CURRENT_TEST");
        if (pt && strstr(pt, "conflict_resolve")) {
         */
        {
            slapi_log_err(SLAPI_LOG_INFO, "dbgec_init", "Starting debbuging the entry cache\n");
            dbgec_debug = 1;
            dbgec_log_init();
        }
    }
}

void dbgec_add_entry(void *addr)
{
    if (dbgec_debug) {
        struct backcommon *entry = addr;
        if (entry && entry->ep_type == CACHE_TYPE_ENTRY) {
            Slapi_Entry *e = (*(Slapi_Entry**)&entry[1]);
            if (e) {
                dbgec_log_add(addr, slapi_entry_get_dn_const(e));
            }
        }
    }
}

void dbgec_rem_entry(void *addr)
{
}

static inline void
dbgec_test_if_entry_pointer_is_valid(void *e, void *prev, int slot, int line)
{
    /* Check if the entry pointer is rightly aligned and crash loudly otherwise */
    if ( ((uint64_t)e) & ((sizeof(long))-1) ) {
        slapi_log_err(SLAPI_LOG_FATAL, "dbgec_test_if_entry_pointer_is_valid", "cache.c[%d]: Wrong entry address: %p Previous entry address is: %p hash table slot is %d\n", line, e, prev, slot);
        dbgec_log_lookup(prev);
        slapi_log_backtrace(SLAPI_LOG_FATAL);
        *(char*)33 = 'a';
        abort();
    }
}

