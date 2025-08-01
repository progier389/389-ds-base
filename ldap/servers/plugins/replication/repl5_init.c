/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc. Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * License: GPL (version 3 or any later version).
 * See LICENSE for details.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


/*
 repl5_init.c - plugin initialization functions
*/

/*
 * Add an entry like the following to dse.ldif to enable this plugin:

dn: cn=Multi-Supplier Replication Plugin,cn=plugins,cn=config
objectclass: top
objectclass: nsSlapdPlugin
objectclass: extensibleObject
cn: Multi-Supplier Replication Plugin
nsslapd-pluginpath: /export2/servers/Hydra-supplier/lib/replication-plugin.so
nsslapd-plugininitfunc: replication_multisupplier_plugin_init
nsslapd-plugintype: object
nsslapd-pluginenabled: on
nsslapd-plugin-depends-on-type: database
nsslapd-plugin-depends-on-named: Class of Service
nsslapd-pluginid: replication-multisupplier
nsslapd-pluginversion: 5.0b1
nsslapd-pluginvendor: Netscape Communications
nsslapd-plugindescription: Multi-Supplier Replication Plugin

*/

#include "slapi-plugin.h"
#include "repl5.h"
#include "cl5.h" /* changelog interface */
#include "plstr.h"

#define NSDS_REPL_NAME_PREFIX "Netscape Replication"

static char *start_oid_list[] = {
    REPL_START_NSDS50_REPLICATION_REQUEST_OID,
    REPL_START_NSDS90_REPLICATION_REQUEST_OID,
    NULL};
static char *start_name_list[] = {
    NSDS_REPL_NAME_PREFIX " Start Session",
    NULL};
static char *end_oid_list[] = {
    REPL_END_NSDS50_REPLICATION_REQUEST_OID,
    NULL};
static char *end_name_list[] = {
    NSDS_REPL_NAME_PREFIX " End Session",
    NULL};
static char *total_oid_list[] = {
    REPL_NSDS50_REPLICATION_ENTRY_REQUEST_OID,
    REPL_NSDS71_REPLICATION_ENTRY_REQUEST_OID,
    NULL};
static char *total_name_list[] = {
    NSDS_REPL_NAME_PREFIX " Total Update Entry",
    NULL};
static char *response_oid_list[] = {
    REPL_NSDS50_REPLICATION_RESPONSE_OID,
    NULL};
static char *response_name_list[] = {
    NSDS_REPL_NAME_PREFIX " Response",
    NULL};
static char *cleanruv_oid_list[] = {
    REPL_CLEANRUV_OID,
    NULL};
static char *cleanruv_name_list[] = {
    NSDS_REPL_NAME_PREFIX " CleanAllRUV",
    NULL};
static char *cleanruv_abort_oid_list[] = {
    REPL_ABORT_CLEANRUV_OID,
    NULL};
static char *cleanruv_abort_name_list[] = {
    NSDS_REPL_NAME_PREFIX " CleanAllRUV Abort",
    NULL};
static char *cleanruv_maxcsn_oid_list[] = {
    REPL_CLEANRUV_GET_MAXCSN_OID,
    NULL};
static char *cleanruv_maxcsn_name_list[] = {
    NSDS_REPL_NAME_PREFIX " CleanAllRUV Retrieve MaxCSN",
    NULL};
static char *cleanruv_status_oid_list[] = {
    REPL_CLEANRUV_CHECK_STATUS_OID,
    NULL};
static char *cleanruv_status_name_list[] = {
    NSDS_REPL_NAME_PREFIX " CleanAllRUV Check Status",
    NULL};


/* List of plugin identities for every plugin registered. Plugin identity
   is passed by the server in the plugin init function and must be supplied
   by the plugin to all internal operations it initiates
 */

/* ----------------------------- Multi-Supplier Replication Plugin */

static Slapi_PluginDesc multisupplierdesc = {"replication-multisupplier", VENDOR, DS_PACKAGE_VERSION, "Multi-supplier Replication Plugin"};
static Slapi_PluginDesc multisupplierpreopdesc = {"replication-multisupplier-preop", VENDOR, DS_PACKAGE_VERSION, "Multi-supplier replication pre-operation plugin"};
static Slapi_PluginDesc multisupplierpostopdesc = {"replication-multisupplier-postop", VENDOR, DS_PACKAGE_VERSION, "Multi-supplier replication post-operation plugin"};
static Slapi_PluginDesc multisupplierinternalpreopdesc = {"replication-multisupplier-internalpreop", VENDOR, DS_PACKAGE_VERSION, "Multi-supplier replication internal pre-operation plugin"};
static Slapi_PluginDesc multisupplierinternalpostopdesc = {"replication-multisupplier-internalpostop", VENDOR, DS_PACKAGE_VERSION, "Multisupplier replication internal post-operation plugin"};
static Slapi_PluginDesc multisupplierbepreopdesc = {"replication-multisupplier-bepreop", VENDOR, DS_PACKAGE_VERSION, "Multisupplier replication bepre-operation plugin"};
static Slapi_PluginDesc multisupplierbemmrdesc = {"replication-multisupplier-bepreop", VENDOR, DS_PACKAGE_VERSION, "Multisupplier replication be plugin"};
static Slapi_PluginDesc multisupplierbepostopdesc = {"replication-multisupplier-bepostop", VENDOR, DS_PACKAGE_VERSION, "Multisupplier replication bepost-operation plugin"};
static Slapi_PluginDesc multisupplierbetxnpostopdesc = {"replication-multisupplier-betxnpostop", VENDOR, DS_PACKAGE_VERSION, "Multisupplier replication be transaction post-operation plugin"};
static Slapi_PluginDesc multisupplierextopdesc = {"replication-multisupplier-extop", VENDOR, DS_PACKAGE_VERSION, "Multisupplier replication extended-operation plugin"};

static int multisupplier_stopped_flag; /* A flag which is set when all the plugin threads are to stop */
static int multisupplier_started_flag = 0;

/* Thread private data and interface */
static PRUintn thread_private_agmtname; /* thread private index for logging*/
static PRUintn thread_private_cache;
static PRUintn thread_primary_csn;

char *
get_thread_private_agmtname()
{
    char *agmtname = NULL;
    if (thread_private_agmtname)
        agmtname = PR_GetThreadPrivate(thread_private_agmtname);
    return (agmtname ? agmtname : "");
}

void
set_thread_private_agmtname(const char *agmtname)
{
    if (thread_private_agmtname)
        PR_SetThreadPrivate(thread_private_agmtname, (void *)agmtname);
}

CSNPL_CTX *
get_thread_primary_csn(void)
{
    CSNPL_CTX *prim_csn = NULL;
    if (thread_primary_csn)
        prim_csn = (CSNPL_CTX *)PR_GetThreadPrivate(thread_primary_csn);

    return prim_csn;
}
void
set_thread_primary_csn(const CSN *prim_csn, Replica *repl)
{
    if (thread_primary_csn) {
        if (prim_csn) {
            CSNPL_CTX *csnpl_ctx = (CSNPL_CTX *)slapi_ch_calloc(1, sizeof(CSNPL_CTX));
            csnpl_ctx->prim_csn = csn_dup(prim_csn);
            /* repl_alloc, repl_cnt and sec_repl are 0 by calloc */
            csnpl_ctx->prim_repl = repl;
            PR_SetThreadPrivate(thread_primary_csn, (void *)csnpl_ctx);
        } else {
            PR_SetThreadPrivate(thread_primary_csn, NULL);
        }
    }
}

void
add_replica_to_primcsn(CSNPL_CTX *csnpl_ctx, Replica *repl)
{
    size_t found = 0;
    size_t it = 0;

    if (repl == csnpl_ctx->prim_repl)
        return;

    while (it < csnpl_ctx->repl_cnt) {
        if (csnpl_ctx->sec_repl[it] == repl) {
            found = 1;
            break;
        }
        it++;
    }
    if (found)
        return;

    if (csnpl_ctx->repl_cnt < csnpl_ctx->repl_alloc) {
        csnpl_ctx->sec_repl[csnpl_ctx->repl_cnt++] = repl;
        return;
    }
    csnpl_ctx->repl_alloc += CSNPL_CTX_REPLCNT;
    if (csnpl_ctx->repl_cnt == 0) {
        csnpl_ctx->sec_repl = (Replica **)slapi_ch_calloc(csnpl_ctx->repl_alloc, sizeof(Replica *));
    } else {
        csnpl_ctx->sec_repl = (Replica **)slapi_ch_realloc((char *)csnpl_ctx->sec_repl, csnpl_ctx->repl_alloc * sizeof(Replica *));
    }
    csnpl_ctx->sec_repl[csnpl_ctx->repl_cnt++] = repl;
    return;
}

void *
get_thread_private_cache()
{
    void *buf = NULL;
    if (thread_private_cache)
        buf = PR_GetThreadPrivate(thread_private_cache);
    return buf;
}

void
set_thread_private_cache(void *buf)
{
    if (thread_private_cache)
        PR_SetThreadPrivate(thread_private_cache, buf);
}

char *
get_repl_session_id(Slapi_PBlock *pb, char *idstr, CSN **csn)
{
    int opid = -1;
    PRUint64 connid = 0;
    CSN *opcsn;
    char opcsnstr[CSN_STRSIZE];

    *idstr = '\0';
    opcsn = NULL;
    opcsnstr[0] = '\0';

    if (pb) {
        Slapi_Operation *op;
        slapi_pblock_get(pb, SLAPI_OPERATION_ID, &opid);
        /* Avoid "Connection is NULL and hence cannot access SLAPI_CONN_ID" */
        if (opid) {
            slapi_pblock_get(pb, SLAPI_CONN_ID, &connid);
            snprintf(idstr, REPL_SESSION_ID_SIZE, "conn=%" PRIu64 " op=%d",
                     connid, opid);
        }

        slapi_pblock_get(pb, SLAPI_OPERATION, &op);
        opcsn = operation_get_csn(op);
        if (opcsn) {
            csn_as_string(opcsn, PR_FALSE, opcsnstr);
            PL_strcatn(idstr, REPL_SESSION_ID_SIZE, " csn=");
            PL_strcatn(idstr, REPL_SESSION_ID_SIZE, opcsnstr);
        }
    }
    if (csn) {
        *csn = opcsn;
    }
    return idstr;
}

/* preop acquires csn generator handle */
int repl5_is_betxn = 0;
int
multisupplier_preop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierpreopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_BIND_FN, (void *)multisupplier_preop_bind) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_ADD_FN, (void *)multisupplier_preop_add) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_DELETE_FN, (void *)multisupplier_preop_delete) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_MODIFY_FN, (void *)multisupplier_preop_modify) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_MODRDN_FN, (void *)multisupplier_preop_modrdn) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_SEARCH_FN, (void *)multisupplier_preop_search) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_COMPARE_FN, (void *)multisupplier_preop_compare) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_ENTRY_FN, (void *)multisupplier_ruv_search) != 0) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_preop_init - Failed\n");
        rc = -1;
    }
    return rc;
}

/* process_postop (core op of post op) frees CSN,
 * which should be called after betxn is finieshed. */
int
multisupplier_postop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierpostopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_BIND_FN, (void *)multisupplier_postop_bind) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_ADD_FN, (void *)multisupplier_postop_add) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_DELETE_FN, (void *)multisupplier_postop_delete) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODIFY_FN, (void *)multisupplier_postop_modify) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODRDN_FN, (void *)multisupplier_postop_modrdn) != 0) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_postop_init - Failed\n");
        rc = -1;
    }

    return rc;
}

int
multisupplier_internalpreop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierinternalpreopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_PRE_ADD_FN, (void *)multisupplier_preop_add) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_PRE_DELETE_FN, (void *)multisupplier_preop_delete) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_PRE_MODIFY_FN, (void *)multisupplier_preop_modify) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_PRE_MODRDN_FN, (void *)multisupplier_preop_modrdn) != 0) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_internalpreop_init - Failed\n");
        rc = -1;
    }
    return rc;
}

int
multisupplier_internalpostop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierinternalpostopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_ADD_FN, (void *)multisupplier_postop_add) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_DELETE_FN, (void *)multisupplier_postop_delete) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_MODIFY_FN, (void *)multisupplier_postop_modify) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_MODRDN_FN, (void *)multisupplier_postop_modrdn) != 0) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_internalpostop_init - Failed\n");
        rc = -1;
    }

    return rc;
}

/*
 * bepreop: setting SLAPI_TXN_RUV_MODS_FN, cleanup old stateinfo.
 * If betxn is off, preop urp is called here, too.
 */
int
multisupplier_bepreop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierbepreopdesc) != 0 ||
        /* slapi_pblock_set(pb, SLAPI_PLUGIN_BE_PRE_CLOSE_FN, (void *)cl5Cleanup) != 0) { */
        slapi_pblock_set(pb, SLAPI_PLUGIN_BE_PRE_CLOSE_FN, (void *)cl5Close) != 0) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_bepreop_init - Failed\n");
        rc = -1;
    }

    return rc;
}

int
multisupplier_mmr_init( Slapi_PBlock *pb )
{
    int rc= 0; /* OK */

    if(slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01 ) != 0 ||
       slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierbemmrdesc ) != 0 ||
       slapi_pblock_set(pb, SLAPI_PLUGIN_MMR_BETXN_PREOP, (void *) multisupplier_mmr_preop ) != 0 ||
       slapi_pblock_set(pb, SLAPI_PLUGIN_MMR_BETXN_POSTOP, (void *) multisupplier_mmr_postop ) != 0) {
       slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_mmr_init - Failed\n" );
       rc= -1;
}

return rc;
}
/*
 * betxnpreop: if betxn is on, call preop urp at betxnpreop.
 */
int
multisupplier_betxnpreop_init(Slapi_PBlock *pb __attribute__((unused)))
{
    int rc = 0; /* OK */

    return rc;
}

/*
 * This bepostop_init is registered only if plugintype is NOT betxn.
 * if plugintype is betxn, callbacks are set in each multisupplier_betxnpostop
 * function.
 */
int
multisupplier_bepostop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierbepostopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_BE_POST_OPEN_FN, (void *)cl5Open) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_BE_POST_MODRDN_FN, (void *)multisupplier_bepostop_modrdn) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_BE_POST_DELETE_FN, (void *)multisupplier_bepostop_delete) != 0) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_bepostop_init - Failed\n");
        rc = -1;
    }

    return rc;
}

/*
 * This betxn_bepostop_init is registered only if plugintype is betxn.
 * Note: other callbacks (add/delete/modify/modrdn) are set in each
 * multisupplier_betxnpostop function.
 */
int
multisupplier_betxn_bepostop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierbepostopdesc) ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_BE_POST_OPEN_FN, (void *)cl5Open) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_BE_POST_EXPORT_FN, (void *)cl5Export) ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_BE_POST_IMPORT_FN, (void *)cl5Import)) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_betxn_bepostop_init - Failed\n");
        rc = -1;
    }

    return rc;
}

int
multisupplier_betxnpostop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */
    void *add_fn;
    void *del_fn;
    void *mod_fn;
    void *mdn_fn;

    if (repl5_is_betxn) {
        /* add_fn = multisupplier_be_betxnpostop_add;
        del_fn = multisupplier_be_betxnpostop_delete;
        mod_fn = multisupplier_be_betxnpostop_modify;
        mdn_fn = multisupplier_be_betxnpostop_modrdn;
        */
        if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                             (void *)&multisupplierbetxnpostopdesc)) {
            slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name,
                          "multisupplier_betxnpostop_init - Failed\n");
            rc = -1;
        }
    } else {
        add_fn = multisupplier_betxnpostop_add;
        del_fn = multisupplier_betxnpostop_delete;
        mod_fn = multisupplier_betxnpostop_modify;
        mdn_fn = multisupplier_betxnpostop_modrdn;

        if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                             (void *)&multisupplierbetxnpostopdesc) ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_POST_ADD_FN, add_fn) ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_POST_DELETE_FN, del_fn) ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_POST_MODRDN_FN, mdn_fn) ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_POST_MODIFY_FN, mod_fn)) {
            slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name,
                          "multisupplier_betxnpostop_init - Failed\n");
            rc = -1;
        }
    }

    return rc;
}

int
multisupplier_start_extop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierextopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, (void *)start_oid_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, (void *)start_name_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *)multisupplier_extop_StartNSDS50ReplicationRequest)) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_start_extop_init  - (StartNSDS50ReplicationRequest) failed\n");
        rc = -1;
    }


    return rc;
}


int
multisupplier_end_extop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */


    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierextopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, (void *)end_oid_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, (void *)end_name_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *)multisupplier_extop_EndNSDS50ReplicationRequest)) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_end_extop_init - (EndNSDS50ReplicationRequest) failed\n");
        rc = -1;
    }

    return rc;
}

int
multisupplier_cleanruv_maxcsn_extop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */
    void *identity = NULL;

    /* get plugin identity and store it to pass to internal operations */
    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &identity);
    PR_ASSERT(identity);

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierextopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, (void *)cleanruv_maxcsn_oid_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, (void *)cleanruv_maxcsn_name_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *)multisupplier_extop_cleanruv_get_maxcsn)) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_cleanruv_maxcsn_extop_init - Failed\n");
        rc = -1;
    }

    return rc;
}

int
multisupplier_cleanruv_status_extop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */
    void *identity = NULL;

    /* get plugin identity and store it to pass to internal operations */
    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &identity);
    PR_ASSERT(identity);

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierextopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, (void *)cleanruv_status_oid_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, (void *)cleanruv_status_name_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *)multisupplier_extop_cleanruv_check_status)) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_cleanruv_status_extop_init - Failed\n");
        rc = -1;
    }

    return rc;
}


int
multisupplier_total_extop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */
    void *identity = NULL;

    /* get plugin identity and store it to pass to internal operations */
    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &identity);
    PR_ASSERT(identity);

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierextopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, (void *)total_oid_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, (void *)total_name_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *)multisupplier_extop_NSDS50ReplicationEntry)) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_total_extop_init - (NSDS50ReplicationEntry failed\n");
        rc = -1;
    }

    return rc;
}

int
multisupplier_response_extop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */
    void *identity = NULL;

    /* get plugin identity and store it to pass to internal operations */
    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &identity);
    PR_ASSERT(identity);

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierextopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, (void *)response_oid_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, (void *)response_name_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *)extop_noop)) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_response_extop_init - (NSDS50ReplicationResponse failed\n");
        rc = -1;
    }

    return rc;
}

int
multisupplier_cleanruv_extop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */
    void *identity = NULL;

    /* get plugin identity and store it to pass to internal operations */
    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &identity);
    PR_ASSERT(identity);

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierextopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, (void *)cleanruv_oid_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, (void *)cleanruv_name_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *)multisupplier_extop_cleanruv)) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_cleanruv_extop_init - Failed\n");
        rc = -1;
    }

    return rc;
}

int
multisupplier_cleanruv_abort_extop_init(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */
    void *identity = NULL;

    /* get plugin identity and store it to pass to internal operations */
    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &identity);
    PR_ASSERT(identity);

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierextopdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, (void *)cleanruv_abort_oid_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, (void *)cleanruv_abort_name_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *)multisupplier_extop_abort_cleanruv)) {
        slapi_log_err(SLAPI_LOG_PLUGIN, repl_plugin_name, "multisupplier_cleanruv_abort_extop_init - Failed\n");
        rc = -1;
    }

    return rc;
}

static PRBool
check_for_ldif_dump(Slapi_PBlock *pb)
{
    int i;
    int argc;
    char **argv;
    PRBool return_value = PR_FALSE;

    slapi_pblock_get(pb, SLAPI_ARGC, &argc);
    slapi_pblock_get(pb, SLAPI_ARGV, &argv);

    for (i = 1; i < argc && !return_value; i++) {
        if (strcmp(argv[i], "db2ldif") == 0) {
            return_value = PR_TRUE;
        }
    }
    return return_value;
}
/*
 * If the entries do not exist, it create the entries of the schema replication policies
 * returns 0 if success
 */
static int
create_repl_schema_policy(void)
{
    /* DN part of this entry_string: no need to be optimized. */
    char entry_string[1024];
    Slapi_PBlock *pb;
    Slapi_Entry *e;
    int return_value;
    char *repl_schema_top, *repl_schema_supplier, *repl_schema_consumer;
    char *default_supplier_policy = NULL;
    char *default_consumer_policy = NULL;
    int rc = 0;

    slapi_schema_get_repl_entries(&repl_schema_top, &repl_schema_supplier, &repl_schema_consumer, &default_supplier_policy, &default_consumer_policy);

    /* Create cn=replSchema,cn=config */
    PR_snprintf(entry_string, sizeof(entry_string), "dn: %s\nobjectclass: top\nobjectclass: nsSchemaPolicy\ncn: replSchema\n", repl_schema_top);
    e = slapi_str2entry(entry_string, 0);
    pb = slapi_pblock_new();
    slapi_add_entry_internal_set_pb(pb, e, NULL, /* controls */
                                    repl_get_plugin_identity(PLUGIN_MULTISUPPLIER_REPLICATION), 0 /* flags */);
    slapi_add_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &return_value);
    if (return_value != LDAP_SUCCESS && return_value != LDAP_ALREADY_EXISTS) {
        slapi_log_err(SLAPI_LOG_ERR, repl_plugin_name, "create_repl_schema_policy - "
                                                       "Unable to create configuration entry %s: %s\n",
                      repl_schema_top,
                      ldap_err2string(return_value));
        rc = -1;
        goto done;
    }
    slapi_pblock_destroy(pb);

    /* Create cn=supplierUpdatePolicy,cn=replSchema,cn=config */
    PR_snprintf(entry_string, sizeof(entry_string), "dn: %s\nobjectclass: top\nobjectclass: nsSchemaPolicy\ncn: supplierUpdatePolicy\n%s",
                repl_schema_supplier,
                default_supplier_policy ? default_supplier_policy : "");
    e = slapi_str2entry(entry_string, 0);
    pb = slapi_pblock_new();
    slapi_add_entry_internal_set_pb(pb, e, NULL, /* controls */
                                    repl_get_plugin_identity(PLUGIN_MULTISUPPLIER_REPLICATION), 0 /* flags */);
    slapi_add_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &return_value);
    if (return_value != LDAP_SUCCESS && return_value != LDAP_ALREADY_EXISTS) {
        slapi_log_err(SLAPI_LOG_ERR, repl_plugin_name, "create_repl_schema_policy - Unable to "
                                                       "create configuration entry %s: %s\n",
                      repl_schema_supplier,
                      ldap_err2string(return_value));
        rc = -1;
        goto done;
    }
    slapi_pblock_destroy(pb);

    /* Create cn=consumerUpdatePolicy,cn=replSchema,cn=config */
    PR_snprintf(entry_string, sizeof(entry_string), "dn: %s\nobjectclass: top\nobjectclass: nsSchemaPolicy\ncn: consumerUpdatePolicy\n%s",
                repl_schema_consumer,
                default_consumer_policy ? default_consumer_policy : "");
    e = slapi_str2entry(entry_string, 0);
    pb = slapi_pblock_new();
    slapi_add_entry_internal_set_pb(pb, e, NULL, /* controls */
                                    repl_get_plugin_identity(PLUGIN_MULTISUPPLIER_REPLICATION), 0 /* flags */);
    slapi_add_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &return_value);
    if (return_value != LDAP_SUCCESS && return_value != LDAP_ALREADY_EXISTS) {
        slapi_log_err(SLAPI_LOG_ERR, repl_plugin_name, "create_repl_schema_policy - "
                                                       "Unable to create configuration entry %s: %s\n",
                      repl_schema_consumer,
                      ldap_err2string(return_value));
        rc = -1;
        goto done;
    }
    slapi_pblock_destroy(pb);
    pb = NULL;

    /* Load the policies of the schema replication */
    if (slapi_schema_load_repl_policies()) {
        slapi_log_err(SLAPI_LOG_ERR, repl_plugin_name, "create_repl_schema_policy - "
                                                       "Unable to load the schema replication policies\n");
        rc = -1;
        goto done;
    }

done:
    slapi_pblock_destroy(pb);
    pb = NULL;

    return rc;
}

static PRBool is_ldif_dump = PR_FALSE;

PRBool
ldif_dump_is_running()
{
    return is_ldif_dump;
}

int
multisupplier_start(Slapi_PBlock *pb)
{
    int rc = 0; /* OK */

    if (!multisupplier_started_flag) {
        /* Get any registered replication session API */
        repl_session_plugin_init();

        /* Initialize thread private data for logging. Ignore if fails */
        PR_NewThreadPrivateIndex(&thread_private_agmtname, NULL);
        PR_NewThreadPrivateIndex(&thread_private_cache, NULL);
        PR_NewThreadPrivateIndex(&thread_primary_csn, csnplFreeCSNPL_CTX);

        /* Decode the command line args to see if we're dumping to LDIF */
        is_ldif_dump = check_for_ldif_dump(pb);

        /* allow online replica configuration */
        rc = replica_config_init();
        if (rc != 0)
            goto out;

        slapi_register_supported_control(REPL_NSDS50_UPDATE_INFO_CONTROL_OID,
                                         SLAPI_OPERATION_ADD | SLAPI_OPERATION_DELETE |
                                             SLAPI_OPERATION_MODIFY | SLAPI_OPERATION_MODDN);

        /* Stash away our partial URL, used in RUVs */
        rc = multisupplier_set_local_purl();
        if (rc != 0)
            goto out;

        /* initialize name hash */
        rc = replica_init_name_hash();
        if (rc != 0)
            goto out;

        /* initialize dn hash */
        rc = replica_init_dn_hash();
        if (rc != 0)
            goto out;

        /* create replicas */
        multisupplier_mtnode_construct_replicas();

        /* Upgrade the 5.0 Changelog if it still exists */
        rc = changelog5_upgrade();
        if (rc != 0)
            goto out;

        /* perform initial changelog setup */
        rc = changelog5_init();
        if (rc != 0)
            goto out;

        rc = create_repl_schema_policy();
        if (rc != 0)
            goto out;

        /* check if the replica's data was reloaded offline and we need
           to reinitialize replica's changelog. This should be done
           after the changelog is initialized */
        replica_enumerate_replicas(replica_check_for_data_reload, NULL);

        /* Initialize the replication agreements, unless we're dumping LDIF */
        if (!is_ldif_dump) {
            rc = agmtlist_config_init();
            if (rc != 0)
                goto out;
        }
        /* register to be notified when backend state changes */
        slapi_register_backend_state_change((void *)multisupplier_be_state_change,
                                            multisupplier_be_state_change);

        multisupplier_started_flag = 1;
        multisupplier_stopped_flag = 0;
    }
out:
    return rc;
}

int
multisupplier_stop(Slapi_PBlock *pb __attribute__((unused)))
{
    int rc = 0; /* OK */

    if (!multisupplier_stopped_flag) {
        if (!is_ldif_dump) {
            /* Shut down replication agreements */
            agmtlist_shutdown();
        }
        /* if we are cleaning a ruv, stop */
        stop_ruv_cleaning();
        /* unregister backend state change notification */
        slapi_unregister_backend_state_change((void *)multisupplier_be_state_change);
        changelog5_cleanup();                   /* Shut down the changelog */
        multisupplier_mtnode_extension_destroy(); /* Destroy mapping tree node exts */
        replica_destroy_name_hash();            /* destroy the hash and its remaining content */
        replica_config_destroy();               /* Destroy replica config info */
        multisupplier_stopped_flag = 1;
    }
    return rc;
}


PRBool
multisupplier_started()
{
    return (multisupplier_started_flag != 0);
}


/*
 * Initialize the multisupplier replication plugin.
 */
int
replication_multisupplier_plugin_init(Slapi_PBlock *pb)
{
    static int multisupplier_initialised = 0;
    int rc = 0; /* OK */
    void *identity = NULL;
    Slapi_Entry *plugin_entry = NULL;

    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &identity);
    PR_ASSERT(identity);
    repl_set_plugin_identity(PLUGIN_MULTISUPPLIER_REPLICATION, identity);

    /* need the repl plugin path for the chain on update function */
    /*    slapi_pblock_get(pb, SLAPI_ADD_ENTRY, &entry);
    PR_ASSERT(entry);
    path = slapi_entry_attr_get_charptr(entry, "nsslapd-pluginpath");
    repl_set_repl_plugin_path(path);
    slapi_ch_free_string(&path);
*/
    multisupplier_mtnode_extension_init();

    if ((slapi_pblock_get(pb, SLAPI_PLUGIN_CONFIG_ENTRY, &plugin_entry) == 0) &&
        plugin_entry) {
        repl5_is_betxn = slapi_entry_attr_get_bool(plugin_entry,
                                                   "nsslapd-pluginbetxn");
    }

    if (!multisupplier_initialised) {
        /* Initialize extensions */
        repl_con_init_ext();
        repl_sup_init_ext();

        rc = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01);
        rc = slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&multisupplierdesc);
        rc = slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN, (void *)multisupplier_start);
        rc = slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN, (void *)multisupplier_stop);

        /* Register the plugin interfaces we implement */
        /* preop acquires csn generator handle */
        rc = slapi_register_plugin("preoperation", 1 /* Enabled */,
                                   "multisupplier_preop_init",
                                   multisupplier_preop_init,
                                   "Multisupplier replication preoperation plugin",
                                   NULL, identity);
        /* Register the main mmr backend plugins */
        rc = slapi_register_plugin("mmr", 1 /* Enabled */,
                                   "multisupplier_mmr_init",
                                   multisupplier_mmr_init,
                                   "Multisupplier replication be operation plugin",
                                   NULL, identity);
        /* bepreop: setting SLAPI_TXN_RUV_MODS_FN and cleanup old stateinfo
         * -- should be done before transaction */
        /* if betxn is off, urp is called at bepreop. */
        rc = slapi_register_plugin("bepreoperation", 1 /* Enabled */,
                                   "multisupplier_bepreop_init",
                                   multisupplier_bepreop_init,
                                   "Multisupplier replication bepreoperation plugin",
                                   NULL, identity);
        /* is_betxn: be post ops (add/del/mod/mdn) are combined into betxn ops.
         * no betxn: be post ops are regsitered at bepostoperation. */
        rc = slapi_register_plugin("betxnpostoperation", 1 /* Enabled */,
                                   "multisupplier_betxnpostop_init",
                                   multisupplier_betxnpostop_init,
                                   "Multisupplier replication betxnpostoperation plugin",
                                   NULL, identity);
        if (repl5_is_betxn) {
            /* if betxn is on, urp is called at betxnpreop. */
            rc = slapi_register_plugin("betxnpreoperation", 1 /* Enabled */,
                                       "multisupplier_betxnpreop_init",
                                       multisupplier_betxnpreop_init,
                                       "Multisupplier replication betxnpreoperation plugin",
                                       NULL, identity);
            /* bepostop configures open and backup only (no betxn) */
            rc = slapi_register_plugin("bepostoperation", 1 /* Enabled */,
                                       "multisupplier_betxn_bepostop_init",
                                       multisupplier_betxn_bepostop_init,
                                       "Multisupplier replication bepostoperation plugin",
                                       NULL, identity);
        } else {
            /* bepostop configures open and backup only as well as add/del/
             * mod/mdn bepost ops */
            rc = slapi_register_plugin("bepostoperation", 1 /* Enabled */,
                                       "multisupplier_bepostop_init",
                                       multisupplier_bepostop_init,
                                       "Multisupplier replication bepostoperation2 plugin",
                                       NULL, identity);
        }
        /* process_postop (core op of post op) frees CSN,
         * which should wait until betxn is done. */
        rc = slapi_register_plugin("postoperation", 1 /* Enabled */,
                                   "multisupplier_postop_init",
                                   multisupplier_postop_init,
                                   "Multisupplier replication postoperation plugin",
                                   NULL, identity);
        rc = slapi_register_plugin("internalpreoperation", 1 /* Enabled */,
                                   "multisupplier_internalpreop_init",
                                   multisupplier_internalpreop_init,
                                   "Multisupplier replication internal preoperation plugin",
                                   NULL, identity);
        rc = slapi_register_plugin("internalpostoperation", 1 /* Enabled */,
                                   "multisupplier_internalpostop_init",
                                   multisupplier_internalpostop_init,
                                   "Multisupplier replication internal postoperation plugin",
                                   NULL, identity);
        rc = slapi_register_plugin("extendedop", 1 /* Enabled */, "multisupplier_start_extop_init", multisupplier_start_extop_init, "Multisupplier replication start extended operation plugin", NULL, identity);
        rc = slapi_register_plugin("extendedop", 1 /* Enabled */, "multisupplier_end_extop_init", multisupplier_end_extop_init, "Multisupplier replication end extended operation plugin", NULL, identity);
        rc = slapi_register_plugin("extendedop", 1 /* Enabled */, "multisupplier_total_extop_init", multisupplier_total_extop_init, "Multisupplier replication total update extended operation plugin", NULL, identity);
        rc = slapi_register_plugin("extendedop", 1 /* Enabled */, "multisupplier_response_extop_init", multisupplier_response_extop_init, "Multisupplier replication extended response plugin", NULL, identity);
        rc = slapi_register_plugin("extendedop", 1 /* Enabled */, "multisupplier_cleanruv_extop_init", multisupplier_cleanruv_extop_init, "Multisupplier replication cleanruv extended operation plugin", NULL, identity);
        rc = slapi_register_plugin("extendedop", 1 /* Enabled */, "multisupplier_cleanruv_abort_extop_init", multisupplier_cleanruv_abort_extop_init, "Multisupplier replication cleanruv abort extended operation plugin", NULL, identity);
        rc = slapi_register_plugin("extendedop", 1 /* Enabled */, "multisupplier_cleanruv_maxcsn_extop_init", multisupplier_cleanruv_maxcsn_extop_init, "Multisupplier replication cleanruv maxcsn extended operation plugin", NULL, identity);
        rc = slapi_register_plugin("extendedop", 1 /* Enabled */, "multisupplier_cleanruv_status_extop_init", multisupplier_cleanruv_status_extop_init, "Multisupplier replication cleanruv status extended operation plugin", NULL, identity);
        if (0 == rc) {
            multisupplier_initialised = 1;
        }
    }
    return rc;
}
