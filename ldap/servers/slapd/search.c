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
 * Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "slap.h"
#include "pratom.h"
#include "snmp_collator.h"

#ifdef SYSTEMTAP
#include <sys/sdt.h>
#endif

static void log_search_access(Slapi_PBlock *pb, const char *base, int scope, const char *filter, const char *msg);

void
do_search(Slapi_PBlock *pb)
{
    Slapi_Operation *operation;
    BerElement *ber;
    int i, err = 0, attrsonly;
    ber_int_t scope, deref, sizelimit, timelimit;
    char *rawbase = NULL;
    int rawbase_set_in_pb = 0; /* was rawbase set in pb? */
    char *base = NULL, *fstr = NULL;
    struct slapi_filter *filter = NULL;
    char **attrs = NULL;
    char **gerattrs = NULL;
    int psearch = 0;
    struct berval *psbvp;
    struct berval *sebvp;
    ber_int_t changetypes;
    int send_entchg_controls;
    int changesonly = 0;
    int rc = -1;
    int strict = 0;
    int minssf_exclude_rootdse = 0;
    int filter_normalized = 0;
    Connection *pb_conn = NULL;

    slapi_log_err(SLAPI_LOG_TRACE, "do_search", "=>\n");
#ifdef SYSTEMTAP
    STAP_PROBE(ns-slapd, do_search__entry);
#endif

    slapi_pblock_get(pb, SLAPI_OPERATION, &operation);
    ber = operation->o_ber;

    /* count the search request */
    slapi_counter_increment(g_get_per_thread_snmp_vars()->ops_tbl.dsSearchOps);

    /*
     * Parse the search request.  It looks like this:
     *
     *    SearchRequest := [APPLICATION 3] SEQUENCE {
     *        baseObject    DistinguishedName,
     *        scope        ENUMERATED {
     *            baseObject    (0),
     *            singleLevel    (1),
     *            wholeSubtree    (2)
     *        },
     *        derefAliases    ENUMERATED {
     *            neverDerefaliases    (0),
     *            derefInSearching    (1),
     *            derefFindingBaseObj    (2),
     *            alwaysDerefAliases    (3)
     *        },
     *        sizelimit    INTEGER (0 .. 65535),
     *        timelimit    INTEGER (0 .. 65535),
     *        attrsOnly    BOOLEAN,
     *        filter        Filter,
     *        attributes    SEQUENCE OF AttributeType
     *    }
     */

    /* baseObject, scope, derefAliases, sizelimit, timelimit, attrsOnly */
    if (ber_scanf(ber, "{aiiiib", &rawbase, &scope, &deref, &sizelimit, &timelimit, &attrsonly) == LBER_ERROR) {
        slapi_ch_free_string(&rawbase);
        log_search_access(pb, "???", -1, "???", "decoding error");
        send_ldap_result(pb, LDAP_PROTOCOL_ERROR, NULL, NULL, 0, NULL);
        return;
    }

    /* Check if we should be performing strict validation. */
    strict = config_get_dn_validate_strict();
    if (strict) {
        /* check that the dn is formatted correctly */
        rc = slapi_dn_syntax_check(pb, rawbase, 1);
        if (rc) { /* syntax check failed */
            op_shared_log_error_access(pb, "SRCH",
                                       rawbase ? rawbase : "", "strict: invalid dn");
            send_ldap_result(pb, LDAP_INVALID_DN_SYNTAX,
                             NULL, "invalid dn", 0, NULL);
            slapi_ch_free_string(&rawbase);
            return;
        }
    }

    if (rawbase && strlen(rawbase) == 0 && scope != LDAP_SCOPE_BASE) {
        /* This is not a Root DSE search, so map it to the default naming context */
        const char *default_basedn = config_get_default_naming_context();
        if (default_basedn) {
            slapi_ch_free_string(&rawbase);
            rawbase = slapi_ch_strdup(default_basedn);
        }
    }

    /* If anonymous access is only allowed for searching the root DSE,
     * we need to reject any other anonymous search attempts. */
    if ((slapi_sdn_get_dn(&(operation->o_sdn)) == NULL) &&
        ((rawbase && strlen(rawbase) > 0) || (scope != LDAP_SCOPE_BASE)) &&
        (config_get_anon_access_switch() == SLAPD_ANON_ACCESS_ROOTDSE)) {
        op_shared_log_error_access(pb, "SRCH", rawbase ? rawbase : "",
                                   "anonymous search not allowed");

        send_ldap_result(pb, LDAP_INAPPROPRIATE_AUTH, NULL,
                         "Anonymous access is not allowed.", 0, NULL);

        goto free_and_return;
    }

    if (slapi_pblock_get(pb, SLAPI_CONNECTION, &pb_conn) != 0 || pb_conn == NULL) {
        slapi_log_err(SLAPI_LOG_ERR, "do_search", "pb_conn is NULL\n");
        goto free_and_return;
    }

    /*
     * If nsslapd-minssf-exclude-rootdse is on, the minssf check has been
     * postponed till this moment since we need to know whether the basedn
     * is rootdse or not.
     *
     * If (minssf_exclude_rootdse && (basedn is rootdse),
     * then we allow accessing rootdse.
     * Otherwise, return Minimum SSF not met.
     */
    minssf_exclude_rootdse = config_get_minssf_exclude_rootdse();
    if (!minssf_exclude_rootdse || (rawbase && strlen(rawbase) > 0)) {
        int minssf = 0;
        /* Check if the minimum SSF requirement has been met. */
        minssf = config_get_minssf();
        if ((pb_conn->c_sasl_ssf < minssf) &&
            (pb_conn->c_ssl_ssf < minssf) &&
            (pb_conn->c_local_ssf < minssf)) {
            op_shared_log_error_access(pb, "SRCH", rawbase ? rawbase : "",
                                       "Minimum SSF not met");
            send_ldap_result(pb, LDAP_UNWILLING_TO_PERFORM, NULL,
                             "Minimum SSF not met.", 0, NULL);
            goto free_and_return;
        }
    }
    base = rawbase;

    /*
     * ignore negative time and size limits since they make no sense
     */
    if (timelimit < 0) {
        timelimit = 0;
    }
    if (sizelimit < 0) {
        sizelimit = 0;
    }

    if (scope != LDAP_SCOPE_BASE && scope != LDAP_SCOPE_ONELEVEL && scope != LDAP_SCOPE_SUBTREE) {
        log_search_access(pb, base, scope, "???", "Unknown search scope");
        send_ldap_result(pb, LDAP_PROTOCOL_ERROR, NULL,
                         "Unknown search scope", 0, NULL);
        goto free_and_return;
    }
    /* check and record the scope for snmp */
    if (scope == LDAP_SCOPE_ONELEVEL) {
        /* count the one level search request */
        slapi_counter_increment(g_get_per_thread_snmp_vars()->ops_tbl.dsOneLevelSearchOps);

    } else if (scope == LDAP_SCOPE_SUBTREE) {
        /* count the subtree search request */
        slapi_counter_increment(g_get_per_thread_snmp_vars()->ops_tbl.dsWholeSubtreeSearchOps);
    }

    /* filter - returns a "normalized" version */
    filter = NULL;
    fstr = NULL;
    if ((err = get_filter(pb_conn, ber, scope, &filter, &fstr)) != 0) {
        char *errtxt;

        if (LDAP_UNWILLING_TO_PERFORM == err) {
            errtxt = "The search filter is too deeply nested";
        } else {
            errtxt = "Bad search filter";
        }
        log_search_access(pb, base, scope, "???", errtxt);
        send_ldap_result(pb, err, NULL, errtxt, 0, NULL);
        goto free_and_return;
    }

    /*
     * Scan the filters syntax - depending on settings, this will do nothing, warn
     * or reject. A question is the location of this and if we should try to work with
     * internal searches too ...
     */
    Slapi_Filter_Result r = slapi_filter_schema_check(pb, filter, config_get_verify_filter_schema());
    if (r == FILTER_SCHEMA_FAILURE) {
        char *errtxt = "The filter provided contains invalid attributes not found in schema";
        err = LDAP_UNWILLING_TO_PERFORM;
        log_search_access(pb, base, scope, "???", errtxt);
        send_ldap_result(pb, err, NULL, errtxt, 0, NULL);
        goto free_and_return;
    }

    /* attributes */
    attrs = NULL;
    if (ber_scanf(ber, "{v}}", &attrs) == LBER_ERROR) {
        log_search_access(pb, base, scope, fstr, "decoding error");
        send_ldap_result(pb, LDAP_PROTOCOL_ERROR, NULL, NULL, 0,
                         NULL);
        err = 1; /* Make sure we free everything */
        goto free_and_return;
    }

    if (attrs != NULL) {
        char *normaci = slapi_attr_syntax_normalize("aci");
        int replace_aci = 0;
        int attr_count = 0;
        int empty_attrs = 0;
        if (!normaci) {
            normaci = slapi_ch_strdup("aci");
        } else if (strcasecmp(normaci, "aci")) {
            /* normaci is not "aci" */
            replace_aci = 1;
        }
        /*
         * . store gerattrs if any
         * . add "aci" once if "*" is given
         * . check that attrs are not degenerated
         */
        for (i = 0; attrs[i] != NULL; i++) {
            char *p = NULL;
            attr_count++;

            if ( attrs[i][0] == '\0') {
                empty_attrs++;
                if (empty_attrs > 10) {
                    log_search_access(pb, base, scope, fstr, "invalid attribute request");
                    send_ldap_result(pb, LDAP_PROTOCOL_ERROR, NULL, NULL, 0, NULL);
                    slapi_ch_free_string(&normaci);
                    err = 1;  /* Make sure we free everything */
                    goto free_and_return;
                }
            }

            /* check if @<objectclass> is included */
            p = strchr(attrs[i], '@');
            if (p) {
                char *dummyary[2];                                                 /* need a char ** for charray_merge_nodup */
                if ((*(p + 1) == '\0') || (p == attrs[i]) || (strchr(p + 1, '@'))) /* e.g. "foo@" or "@objectclassname" or "foo@bar@baz" */
                {
                    slapi_log_err(SLAPI_LOG_ARGS, "do_search",
                                  "invalid attribute [%s] in list - must be of the form "
                                  "attributename@objectclassname where attributename is the "
                                  "name of an attribute or \"*\" or \"+\" and objectclassname "
                                  "is the name of an objectclass\n",
                                  attrs[i]);
                    continue;
                }
                dummyary[0] = p; /* p = @objectclassname */
                dummyary[1] = NULL;
                /* copy string to gerattrs with leading @ - disallow dups */
                charray_merge_nodup(&gerattrs, dummyary, 1);
                /* null terminate the attribute name at the @ after it has been copied */
                *p = '\0';
            } else if (strcmp(attrs[i], LDAP_ALL_USER_ATTRS /* '*' */) == 0) {
                if (!charray_inlist(attrs, normaci)) {
                    charray_add(&attrs, slapi_ch_strdup(normaci));
                    attr_count++;
                }
            } else if (replace_aci && (strcasecmp(attrs[i], "aci") == 0)) {
                slapi_ch_free_string(&attrs[i]);
                attrs[i] = slapi_ch_strdup(normaci);
            }
        }
        slapi_ch_free_string(&normaci);

        if (config_get_return_orig_type_switch()) {
            /* return the original type, e.g., "sn (surname)" */
            operation->o_searchattrs = charray_dup(attrs);
            for (i = 0; attrs[i] != NULL; i++) {
                char *type;
                type = slapi_attr_syntax_normalize(attrs[i]);
                slapi_ch_free((void **)&(attrs[i]));
                attrs[i] = type;
            }
        } else {
            /* return the chopped type, e.g., "sn" */
            operation->o_searchattrs = (char **)slapi_ch_calloc(sizeof(char *), attr_count+1);
            for (i = 0; attrs[i] != NULL; i++) {
                char *type;
                type = slapi_attr_syntax_normalize_ext(attrs[i],
                                                       ATTR_SYNTAX_NORM_ORIG_ATTR);
                /* attrs[i] is consumed */
                operation->o_searchattrs[i] = attrs[i];
                attrs[i] = type;
            }
        }
    }
    if (slapd_ldap_debug & LDAP_DEBUG_ARGS) {
        char abuf[1024], *astr;

        if (NULL == attrs) {
            astr = "ALL";
        } else {
            strarray2str(attrs, abuf, sizeof(abuf), 1 /* include quotes */);
            astr = abuf;
        }
        slapi_log_err(SLAPI_LOG_ARGS, "do_search", "SRCH base=\"%s\" "
                                                   "scope=%d deref=%d "
                                                   "sizelimit=%d timelimit=%d attrsonly=%d filter=\"%s\" "
                                                   "attrs=%s\n",
                      base, scope, deref, sizelimit, timelimit,
                      attrsonly, fstr, astr);
    }

    /*
     * in LDAPv3 there can be optional control extensions on
     * the end of an LDAPMessage. we need to read them in and
     * pass them to the backend. get_ldapmessage_controls()
     * reads the controls and sets any we know about in the pb.
     */
    if ((err = get_ldapmessage_controls(pb, ber, NULL)) != 0) {
        log_search_access(pb, base, scope, fstr, "failed to decode LDAP controls");
        send_ldap_result(pb, err, NULL, NULL, 0, NULL);
        goto free_and_return;
    }

    /* we support persistent search for regular operations only */
    if (slapi_control_present(operation->o_params.request_controls,
                              LDAP_CONTROL_PERSISTENTSEARCH, &psbvp, NULL)) {
        operation_set_flag(operation, OP_FLAG_PS);
        psearch = 1;
        if (ps_parse_control_value(psbvp, &changetypes,
                                   &changesonly, &send_entchg_controls) != LDAP_SUCCESS) {
            changetypes = LDAP_CHANGETYPE_ANY;
            send_entchg_controls = 0;
        } else if (changesonly) {
            operation_set_flag(operation, OP_FLAG_PS_CHANGESONLY);
        }
    }

    /* Whether or not to return subentries vs normal entries */
    int is_subentries_critical = 0;
    if (slapi_control_present(operation->o_params.request_controls,
                              LDAP_CONTROL_SUBENTRIES, &sebvp, &is_subentries_critical)) {
        int subentries_visibility = subentries_parse_request_control(sebvp);
        if (subentries_visibility < 0) {
            /* Something went wrong decoding subenrties control */
            log_search_access(pb, base, scope, fstr, "failed to decode LDAP Subentries control");
            if (is_subentries_critical) {
                send_ldap_result(pb, LDAP_PROTOCOL_ERROR, NULL, NULL, 0, NULL);
                goto free_and_return;
            }
        } else {
            if (subentries_visibility == 0) {
                operation_set_flag(operation, OP_FLAG_SUBENTRIES_FALSE);
            } else if (subentries_visibility == 1) {
                operation_set_flag(operation, OP_FLAG_SUBENTRIES_TRUE);
            }
        }
    }

    slapi_pblock_set(pb, SLAPI_ORIGINAL_TARGET_DN, rawbase);
    rawbase_set_in_pb = 1; /* rawbase is now owned by pb */
    slapi_pblock_set(pb, SLAPI_SEARCH_SCOPE, &scope);
    slapi_pblock_set(pb, SLAPI_SEARCH_DEREF, &deref);
    slapi_pblock_set(pb, SLAPI_SEARCH_FILTER, filter);
    slapi_pblock_set(pb, SLAPI_PLUGIN_SYNTAX_FILTER_NORMALIZED,
                     &filter_normalized);
    slapi_pblock_set(pb, SLAPI_SEARCH_STRFILTER, fstr);
    slapi_pblock_set(pb, SLAPI_SEARCH_ATTRS, attrs);
    slapi_pblock_set(pb, SLAPI_SEARCH_GERATTRS, gerattrs);
    slapi_pblock_set(pb, SLAPI_SEARCH_ATTRSONLY, &attrsonly);
    slapi_pblock_set(pb, SLAPI_REQUESTOR_ISROOT, &operation->o_isroot);
    slapi_pblock_set(pb, SLAPI_SEARCH_SIZELIMIT, &sizelimit);
    slapi_pblock_set(pb, SLAPI_SEARCH_TIMELIMIT, &timelimit);


    /*
     * op_shared_search defines STAP_PROBE for __entry and __return,
     * so these can be used to delineate the start and end here.
     */
    op_shared_search(pb, psearch ? 0 : 1 /* send result */);

    slapi_pblock_get(pb, SLAPI_PLUGIN_OPRETURN, &rc);
    slapi_pblock_get(pb, SLAPI_SEARCH_FILTER, &filter);

    if (psearch && rc == 0) {
        ps_add(pb, changetypes, send_entchg_controls);
    }

free_and_return:
    if (!psearch || rc != 0 || err != 0) {
        slapi_ch_free_string(&fstr);
        slapi_filter_free(filter, 1);

        /* Get attrs from pblock if it was set there, otherwise use local attrs */
        char **pblock_attrs = NULL;
        slapi_pblock_get(pb, SLAPI_SEARCH_ATTRS, &pblock_attrs);
        if (pblock_attrs != NULL) {
            charray_free(pblock_attrs); /* Free attrs from pblock */
            slapi_pblock_set(pb, SLAPI_SEARCH_ATTRS, NULL);
        } else if (attrs != NULL) {
            /* Free attrs that were allocated but never put in pblock */
            charray_free(attrs);
        }
        charray_free(gerattrs); /* passing NULL is fine */
        /*
         * Fix for defect 526719 / 553356 : Persistent search op failed.
         * Marking it as non-persistent so that operation resources get freed
         */
        if (psearch) {
            operation->o_flags &= ~OP_FLAG_PS;
        }
        /* we strdup'd this above - need to free */
        if (rawbase_set_in_pb) {
            slapi_pblock_get(pb, SLAPI_ORIGINAL_TARGET_DN, &rawbase);
        }
        slapi_ch_free_string(&rawbase);
    }

#ifdef SYSTEMTAP
    STAP_PROBE(ns-slapd, do_search__return);
#endif
}

static void
log_search_access(Slapi_PBlock *pb, const char *base, int scope, const char *fstr, const char *msg)
{
    Operation *pb_op;
    Connection *pb_conn;
    slapi_pblock_get(pb, SLAPI_CONNECTION, &pb_conn);
    slapi_pblock_get(pb, SLAPI_OPERATION, &pb_op);
    slapi_log_access(LDAP_DEBUG_STATS,
                     "conn=%" PRIu64 " op=%d SRCH base=\"%s\" scope=%d filter=\"%s\", %s\n",
                     pb_conn->c_connid, pb_op->o_opid,
                     base, scope, fstr, msg ? msg : "");
}
