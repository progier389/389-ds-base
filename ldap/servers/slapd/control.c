/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc. Used by permission.
 * Copyright (C) 2025 Red Hat, Inc.
 * All rights reserved.
 *
 * License: GPL (version 3 or any later version).
 * See LICENSE for details.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* control.c - routines for dealing with LDAPMessage controls */

#include <stdio.h>
#include <plbase64.h>
#include "slap.h"


/*
 * static variables used to track information about supported controls.
 * supported_controls is a NULL-terminated array of OIDs.
 * supported_controls_ops is an array of bitmaps that hold SLAPI_OPERATION_*
 *    flags that specify the operation(s) for which a control is supported.
 *    The elements in the supported_controls_ops array align with the ones
 *    in the supported_controls array.
 */
static char **supported_controls = NULL;
static unsigned long *supported_controls_ops = NULL;
static int supported_controls_count = 0;
static Slapi_RWLock *supported_controls_lock = NULL;

/*
 * Register all of the LDAPv3 controls we know about "out of the box."
 */
void
init_controls(void)
{
    supported_controls_lock = slapi_new_rwlock();
    if (NULL == supported_controls_lock) {
        /* Out of resources */
        slapi_log_err(SLAPI_LOG_ERR, "init_controls",
                      "Failed to create lock.\n");
        exit(1);
    }

    slapi_register_supported_control(LDAP_CONTROL_MANAGEDSAIT,
                                     SLAPI_OPERATION_SEARCH | SLAPI_OPERATION_COMPARE | SLAPI_OPERATION_ADD | SLAPI_OPERATION_DELETE | SLAPI_OPERATION_MODIFY | SLAPI_OPERATION_MODDN);
    slapi_register_supported_control(LDAP_CONTROL_PERSISTENTSEARCH,
                                     SLAPI_OPERATION_SEARCH);
    slapi_register_supported_control(LDAP_CONTROL_PWEXPIRED,
                                     SLAPI_OPERATION_NONE);
    slapi_register_supported_control(LDAP_CONTROL_PWEXPIRING,
                                     SLAPI_OPERATION_NONE);
    slapi_register_supported_control(LDAP_CONTROL_SORTREQUEST,
                                     SLAPI_OPERATION_SEARCH);
    slapi_register_supported_control(LDAP_CONTROL_VLVREQUEST,
                                     SLAPI_OPERATION_SEARCH);
    slapi_register_supported_control(LDAP_CONTROL_AUTH_REQUEST,
                                     SLAPI_OPERATION_BIND);
    slapi_register_supported_control(LDAP_CONTROL_AUTH_RESPONSE,
                                     SLAPI_OPERATION_NONE);
    slapi_register_supported_control(LDAP_CONTROL_REAL_ATTRS_ONLY,
                                     SLAPI_OPERATION_SEARCH);
    slapi_register_supported_control(LDAP_CONTROL_VIRT_ATTRS_ONLY,
                                     SLAPI_OPERATION_SEARCH);
    slapi_register_supported_control(LDAP_CONTROL_PRE_READ_ENTRY,
                                     SLAPI_OPERATION_DELETE | SLAPI_OPERATION_MODIFY |
                                         SLAPI_OPERATION_MODDN);
    slapi_register_supported_control(LDAP_CONTROL_POST_READ_ENTRY,
                                     SLAPI_OPERATION_ADD | SLAPI_OPERATION_MODIFY |
                                         SLAPI_OPERATION_MODDN);
    slapi_register_supported_control(LDAP_X_CONTROL_PWPOLICY_REQUEST,
                                     SLAPI_OPERATION_SEARCH | SLAPI_OPERATION_COMPARE | SLAPI_OPERATION_ADD | SLAPI_OPERATION_DELETE | SLAPI_OPERATION_MODIFY | SLAPI_OPERATION_MODDN);
    slapi_register_supported_control(LDAP_CONTROL_SUBENTRIES,
                                     SLAPI_OPERATION_SEARCH);

    /*
    We do not register the password policy response because it has
    the same oid as the request (and it was being reported twice in
    in the root DSE supportedControls attribute)

    slapi_register_supported_control( LDAP_X_CONTROL_PWPOLICY_RESPONSE,
        SLAPI_OPERATION_SEARCH | SLAPI_OPERATION_COMPARE
        | SLAPI_OPERATION_ADD | SLAPI_OPERATION_DELETE
        | SLAPI_OPERATION_MODIFY | SLAPI_OPERATION_MODDN );
*/
    slapi_register_supported_control(LDAP_CONTROL_GET_EFFECTIVE_RIGHTS,
                                     SLAPI_OPERATION_SEARCH);

    /* LDAP_CONTROL_PAGEDRESULTS is shared by request and response */
    slapi_register_supported_control(LDAP_CONTROL_PAGEDRESULTS,
                                     SLAPI_OPERATION_SEARCH);

    /* LDAP_CONTROL_X_SESSION_TRACKING only supported by request */
    slapi_register_supported_control(LDAP_CONTROL_X_SESSION_TRACKING,
                                     SLAPI_OPERATION_BIND | SLAPI_OPERATION_UNBIND | SLAPI_OPERATION_ABANDON | SLAPI_OPERATION_EXTENDED | SLAPI_OPERATION_SEARCH | SLAPI_OPERATION_COMPARE | SLAPI_OPERATION_ADD | SLAPI_OPERATION_DELETE | SLAPI_OPERATION_MODIFY | SLAPI_OPERATION_MODDN);
}


/*
 * register a supported control so it can be returned as part of the root DSE.
 */
void
slapi_register_supported_control(char *controloid, unsigned long controlops)
{
    if (controloid != NULL) {
        slapi_rwlock_wrlock(supported_controls_lock);
        ++supported_controls_count;
        charray_add(&supported_controls, slapi_ch_strdup(controloid));
        supported_controls_ops = (unsigned long *)slapi_ch_realloc(
            (char *)supported_controls_ops,
            supported_controls_count * sizeof(unsigned long));
        supported_controls_ops[supported_controls_count - 1] =
            controlops;
        slapi_rwlock_unlock(supported_controls_lock);
    }
}


/*
 * retrieve supported controls OID and/or operations arrays.
 * return 0 if successful and -1 if not.
 * This function is not MTSafe and should be deprecated.
 * slapi_get_supported_controls_copy should be used instead.
 */
int
slapi_get_supported_controls(char ***ctrloidsp, unsigned long **ctrlopsp)
{
    if (ctrloidsp != NULL) {
        *ctrloidsp = supported_controls;
    }
    if (ctrlopsp != NULL) {
        *ctrlopsp = supported_controls_ops;
    }

    return (0);
}


static unsigned long *
supported_controls_ops_dup(unsigned long *ctrlops __attribute__((unused)))
{
    int i;
    unsigned long *dup_ops = (unsigned long *)slapi_ch_calloc(
        supported_controls_count + 1, sizeof(unsigned long));
    if (NULL != dup_ops) {
        for (i = 0; i < supported_controls_count; i++)
            dup_ops[i] = supported_controls_ops[i];
    }
    return dup_ops;
}


int
slapi_get_supported_controls_copy(char ***ctrloidsp, unsigned long **ctrlopsp)
{
    slapi_rwlock_rdlock(supported_controls_lock);
    if (ctrloidsp != NULL) {
        *ctrloidsp = charray_dup(supported_controls);
    }
    if (ctrlopsp != NULL) {
        *ctrlopsp = supported_controls_ops_dup(supported_controls_ops);
    }
    slapi_rwlock_unlock(supported_controls_lock);
    return (0);
}

int
create_sessiontracking_ctrl(const char *session_tracking_id, LDAPControl **session_tracking_ctrl)
{
    BerElement *ctrlber = NULL;
    char *undefined_sid = "undefined sid";
    char *sid;
    int rc = 0;
    int tag;
    LDAPControl *ctrl = NULL;

    if (session_tracking_id) {
        sid = session_tracking_id;
    } else {
        sid = undefined_sid;
    }
    ctrlber = ber_alloc();
    tag = ber_printf( ctrlber, "{nnno}", sid, strlen(sid));
    if (rc == LBER_ERROR) {
        tag = -1;
        goto done;
    }
    slapi_build_control(LDAP_CONTROL_X_SESSION_TRACKING, ctrlber, 0, &ctrl);
    *session_tracking_ctrl = ctrl;

done:
    if (ctrlber) {
        ber_free(ctrlber, 1);
    }
    return rc;
}

/* Parse the Session Tracking control
 * see https://datatracker.ietf.org/doc/html/draft-wahl-ldap-session-03
 *    LDAPString ::= OCTET STRING -- UTF-8 encoded
 *    LDAPOID ::= OCTET STRING -- Constrained to numericoid
 *
 *      SessionIdentifierControlValue ::= SEQUENCE {
 *            sessionSourceIp                 LDAPString,
 *            sessionSourceName               LDAPString,
 *            formatOID                       LDAPOID,
 *            sessionTrackingIdentifier       LDAPString
 *       }
 *
 * design https://www.port389.org/docs/389ds/design/session-identifier-in-logs.html
 *
 * It ignores sessionSourceIp, sessionSourceName and formatOID.
 * It extracts the 15 first chars from sessionTrackingIdentifier (escaped)
 * and return them in session_tracking_id (allocated buffer)
 * The caller is responsible of the free of session_tracking_id
 */
static int
parse_sessiontracking_ctrl(struct berval *session_tracking_spec, char **session_tracking_id)
{
    BerElement *ber = NULL;
    ber_tag_t ber_rc;
    struct berval sessionTrackingIdentifier = {0};
#define SESSION_ID_STR_SZ 15
#define NB_DOTS            3
    char buf_sid_orig[SESSION_ID_STR_SZ + 2] = {0};
    const char *buf_sid_escaped;
    int32_t sid_escaped_sz; /* size of the escaped sid that we retain */
    char buf[BUFSIZ];
    char *sid;
    int rc = LDAP_SUCCESS;

    if (!BV_HAS_DATA(session_tracking_spec)) {
        return LDAP_PROTOCOL_ERROR;
    }
    ber = ber_init(session_tracking_spec);
    if ((ber == NULL) || (session_tracking_id == NULL)) {
        return LDAP_OPERATIONS_ERROR;
    }

    *session_tracking_id = NULL;

    /* Discard sessionSourceIp, sessionSourceName and formatOID
     * Then only get sessionTrackingIdentifier and truncate it if needed */
    ber_rc = ber_scanf(ber, "{xxxo}", &sessionTrackingIdentifier);
    if ((ber_rc == LBER_ERROR) || (sessionTrackingIdentifier.bv_len > 65536)) {
        rc = LDAP_PROTOCOL_ERROR;
        goto free_and_return;
    }

    /* Make sure the interesting part of the provided SID is escaped */
    if (sessionTrackingIdentifier.bv_len > SESSION_ID_STR_SZ) {
        memcpy(buf_sid_orig, sessionTrackingIdentifier.bv_val, SESSION_ID_STR_SZ + 1);
    } else {
        memcpy(buf_sid_orig, sessionTrackingIdentifier.bv_val, sessionTrackingIdentifier.bv_len);
    }
    buf_sid_escaped = escape_string(buf_sid_orig, buf);

    /* Allocate the buffer that contains the heading portion
     * of the escaped SID
     */
    sid_escaped_sz = strlen(buf_sid_escaped);
    if (sid_escaped_sz > SESSION_ID_STR_SZ) {
        /* Take only a portion of it plus some '.' */
        sid_escaped_sz = SESSION_ID_STR_SZ + NB_DOTS;
    }
    sid = (char *) slapi_ch_calloc(1, sid_escaped_sz + 1);

    /* Lets copy the escaped SID into the buffer */
    if (sid_escaped_sz > SESSION_ID_STR_SZ) {
        memcpy(sid, buf_sid_escaped, SESSION_ID_STR_SZ);
        memset(sid + SESSION_ID_STR_SZ, '.', NB_DOTS); /* ending the string with "..." */
    } else {
        memcpy(sid, buf_sid_escaped, sid_escaped_sz);
    }
    sid[sid_escaped_sz] = '\0';

    *session_tracking_id = sid;

free_and_return:
    if (ber != NULL) {
        ber_free(ber, 1);
        ber = NULL;
    }
    slapi_ch_free_string(&sessionTrackingIdentifier.bv_val);

    return rc;
}

/*
 * RFC 4511 section 4.1.11.  Controls says that the UnbindRequest
 * MUST ignore the criticality field of controls
 */
int
get_ldapmessage_controls_ext(
    Slapi_PBlock *pb,
    BerElement *ber,
    LDAPControl ***controlsp, /* can be NULL if no need to return */
    int ignore_criticality    /* some requests must ignore criticality */
    )
{
    LDAPControl **ctrls, *new;
    ber_tag_t tag;
    /* ber_len_t is uint, cannot be -1 */
    ber_len_t len = LBER_ERROR;
    int rc, maxcontrols, curcontrols;
    char *last;
    int managedsait, pwpolicy_ctrl;
    Connection *pb_conn = NULL;

    /*
     * Each LDAPMessage can have a set of controls appended
     * to it. Controls are used to extend the functionality
     * of an LDAP operation (e.g., add an attribute size limit
     * to the search operation). These controls look like this:
     *
     *    Controls ::= SEQUENCE OF Control
     *
     *    Control ::= SEQUENCE {
     *        controlType    LDAPOID,
     *        criticality    BOOLEAN DEFAULT FALSE,
     *        controlValue    OCTET STRING
     *    }
     */

    slapi_log_err(SLAPI_LOG_TRACE, "get_ldapmessage_controls_ext", "=> get_ldapmessage_controls\n");

    if (!pb) {
        slapi_log_err(SLAPI_LOG_ERR, "get_ldapmessage_controls_ext", "<= NULL PBlock\n");
        return (LDAP_OPERATIONS_ERROR); /* unexpected error */
    }

    ctrls = NULL;
    /* coverity[var_deref_model] */
    slapi_pblock_set(pb, SLAPI_REQCONTROLS, ctrls);
    if (controlsp != NULL) {
        *controlsp = NULL;
    }
    rc = LDAP_PROTOCOL_ERROR; /* most popular error we may return */

    /*
         * check to see if controls were included
     */
    if (ber_get_option(ber, LBER_OPT_REMAINING_BYTES, &len) != 0) {
        slapi_log_err(SLAPI_LOG_TRACE, "get_ldapmessage_controls_ext",
                      "<= LDAP_OPERATIONS_ERROR\n");
        return (LDAP_OPERATIONS_ERROR); /* unexpected error */
    }
    if (len == 0) {
        slapi_log_err(SLAPI_LOG_TRACE, "get_ldapmessage_controls_ext",
                      "<= no controls\n");
        return (LDAP_SUCCESS); /* no controls */
    }
    if ((tag = ber_peek_tag(ber, &len)) != LDAP_TAG_CONTROLS) {
        if (tag == LBER_ERROR) {
            slapi_log_err(SLAPI_LOG_TRACE, "get_ldapmessage_controls_ext",
                          "<= LDAP_PROTOCOL_ERROR\n");
            return (LDAP_PROTOCOL_ERROR); /* decoding error */
        }
        /*
         * We found something other than controls.  This should never
         * happen in LDAPv3, but we don't treat this is a hard error --
         * we just ignore the extra stuff.
         */
        slapi_log_err(SLAPI_LOG_TRACE, "get_ldapmessage_controls_ext",
                      "<= ignoring unrecognized data in request (tag 0x%x)\n", (unsigned int)tag);
        return (LDAP_SUCCESS);
    }

    /*
     * A sequence of controls is present.  If connection is not LDAPv3
     * or better, return a protocol error.  Otherwise, parse the controls.
     */
    slapi_pblock_get(pb, SLAPI_CONNECTION, &pb_conn);

    if (pb_conn != NULL && pb_conn->c_ldapversion < LDAP_VERSION3) {
        slapi_log_err(SLAPI_LOG_ERR, "get_ldapmessage_controls_ext",
                      "Received control(s) on an LDAPv%d connection\n",
                      pb_conn->c_ldapversion);
        return (LDAP_PROTOCOL_ERROR);
    }

    maxcontrols = curcontrols = 0;
    for (tag = ber_first_element(ber, &len, &last);
         tag != LBER_ERROR && tag != LBER_END_OF_SEQORSET;
         tag = ber_next_element(ber, &len, last)) {
        len = -1; /* reset */
        if (curcontrols >= maxcontrols - 1) {
#define CONTROL_GRABSIZE 6
            maxcontrols += CONTROL_GRABSIZE;
            ctrls = (LDAPControl **)slapi_ch_realloc((char *)ctrls,
                                                     maxcontrols * sizeof(LDAPControl *));
        }
        new = (LDAPControl *)slapi_ch_calloc(1, sizeof(LDAPControl));
        ctrls[curcontrols++] = new;
        ctrls[curcontrols] = NULL;

        if (ber_scanf(ber, "{a", &new->ldctl_oid) == LBER_ERROR) {
            goto free_and_return;
        }

        /* the criticality is optional */
        if (ber_peek_tag(ber, &len) == LBER_BOOLEAN) {
            if (ber_scanf(ber, "b", &new->ldctl_iscritical) == LBER_ERROR) {
                goto free_and_return;
            }
        } else {
            /* absent is synonomous with FALSE */
            new->ldctl_iscritical = 0;
        }
        len = -1; /* reset */
        /* if we are ignoring criticality, treat as FALSE */
        if (ignore_criticality) {
            new->ldctl_iscritical = 0;
        }

        /*
         * return an appropriate error if this control is marked
         * critical and either:
         *   a) we do not support it at all OR
         *   b) it is not supported for this operation
         */
        if (new->ldctl_iscritical) {
            int i;

            slapi_rwlock_rdlock(supported_controls_lock);
            for (i = 0; supported_controls != NULL && supported_controls[i] != NULL; ++i) {
                if (strcmp(supported_controls[i],
                           new->ldctl_oid) == 0) {
                    break;
                }
            }

            Operation *pb_op = NULL;
            slapi_pblock_get(pb, SLAPI_OPERATION, &pb_op);
            if (pb_op == NULL) {
                rc = LDAP_OPERATIONS_ERROR;
                slapi_log_err(SLAPI_LOG_ERR, "get_ldapmessage_controls_ext", "NULL pb_op\n");
                slapi_rwlock_unlock(supported_controls_lock);
                goto free_and_return;
            }

            if (supported_controls == NULL ||
                supported_controls[i] == NULL ||
                (0 == (supported_controls_ops[i] &
                       operation_get_type(pb_op)))) {
                rc = LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
                slapi_rwlock_unlock(supported_controls_lock);
                goto free_and_return;
            }
            slapi_rwlock_unlock(supported_controls_lock);
        }

        /* the control value is optional */
        if (ber_peek_tag(ber, &len) == LBER_OCTETSTRING) {
            if (ber_scanf(ber, "o", &new->ldctl_value) == LBER_ERROR) {
                goto free_and_return;
            }
        } else {
            (new->ldctl_value).bv_val = NULL;
            (new->ldctl_value).bv_len = 0;
        }
        len = -1; /* reset for next loop iter */
    }

    if (curcontrols == 0) {
        int ctrl_not_found = 0; /* means that a given control is not present in the request */
        Operation *pb_op = NULL;
        slapi_pblock_get(pb, SLAPI_OPERATION, &pb_op);

        slapi_pblock_set(pb, SLAPI_REQCONTROLS, NULL);
        slapi_pblock_set(pb, SLAPI_MANAGEDSAIT, &ctrl_not_found);
        slapi_pblock_set(pb, SLAPI_PWPOLICY, &ctrl_not_found);
        slapi_pblock_set(pb, SLAPI_SESSION_TRACKING, NULL);
        slapi_log_err(SLAPI_LOG_CONNS, "get_ldapmessage_controls_ext", "Warning: conn=%" PRIu64 " op=%d contains an empty list of controls\n",
                      pb_conn ? pb_conn->c_connid : -1, pb_op ? pb_op->o_opid : -1);
    } else {
        struct berval *session_tracking_spec = NULL;
        int iscritical = 0;
        char *session_tracking_id = NULL;
        char *old_sid;
        int parse_rc = 0;

        /* len, ber_len_t is uint, not int, cannot be != -1, may be better to remove this check.  */
        if ((tag != LBER_END_OF_SEQORSET) && (len != -1)) {
            goto free_and_return;
        }

        slapi_pblock_set(pb, SLAPI_REQCONTROLS, ctrls);
        managedsait = slapi_control_present(ctrls,
                                            LDAP_CONTROL_MANAGEDSAIT, NULL, NULL);
        slapi_pblock_set(pb, SLAPI_MANAGEDSAIT, &managedsait);
        if (slapi_control_present(ctrls,
                                  LDAP_CONTROL_X_SESSION_TRACKING, &session_tracking_spec, &iscritical)) {
            Operation *pb_op = NULL;
            slapi_pblock_get(pb, SLAPI_OPERATION, &pb_op);

            if (iscritical) {
                /* It must not be critical */
                slapi_log_err(SLAPI_LOG_ERR, "get_ldapmessage_controls_ext", "conn=%" PRIu64 " op=%d SessionTracking critical flag must be unset\n",
                              pb_conn ? pb_conn->c_connid : -1, pb_op ? pb_op->o_opid : -1);
                rc = LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
                goto free_and_return;
            }
            parse_rc = parse_sessiontracking_ctrl(session_tracking_spec, &session_tracking_id);
            if (parse_rc != LDAP_SUCCESS) {
                slapi_log_err(SLAPI_LOG_WARNING, "get_ldapmessage_controls_ext", "Warning: conn=%" PRIu64 " op=%d failed to parse SessionTracking control (%d)\n",
                              pb_conn ? pb_conn->c_connid : -1, pb_op ? pb_op->o_opid : -1, parse_rc);
                slapi_ch_free_string(&session_tracking_id);
            } else {
                /* now replace the sid (if any) in the pblock */
                slapi_pblock_get(pb, SLAPI_SESSION_TRACKING, &old_sid);
                slapi_ch_free_string(&old_sid);
                slapi_pblock_set(pb, SLAPI_SESSION_TRACKING, session_tracking_id);
            }
        }
        slapi_pblock_set(pb, SLAPI_SESSION_TRACKING, session_tracking_id);
        pwpolicy_ctrl = slapi_control_present(ctrls,
                                              LDAP_X_CONTROL_PWPOLICY_REQUEST, NULL, NULL);
        slapi_pblock_set(pb, SLAPI_PWPOLICY, &pwpolicy_ctrl);
    }

    if (controlsp != NULL) {
        *controlsp = ctrls;
    }

#ifdef SLAPD_ECHO_CONTROL
    /*
     * XXXmcs: Start of hack: if a control with OID "1.1" was sent by
     * the client, echo all controls back to the client unchanged.  Note
     * that this is just a hack to test control handling in libldap and
     * should be removed once we support all interesting controls.
     */
    if (slapi_control_present(ctrls, "1.1", NULL, NULL)) {
        int i;

        for (i = 0; ctrls[i] != NULL; ++i) {
            slapi_pblock_set(pb, SLAPI_ADD_RESCONTROL,
                             (void *)ctrls[i]);
        }
    }
#endif /* SLAPD_ECHO_CONTROL */

    slapi_log_err(SLAPI_LOG_TRACE, "get_ldapmessage_controls_ext",
                  "<= %d controls\n", curcontrols);
    return (LDAP_SUCCESS);

free_and_return:;
    ldap_controls_free(ctrls);
    slapi_log_err(SLAPI_LOG_TRACE, "get_ldapmessage_controls_ext",
                  "<= %i\n", rc);
    return (rc);
}

int
get_ldapmessage_controls(
    Slapi_PBlock *pb,
    BerElement *ber,
    LDAPControl ***controlsp /* can be NULL if no need to return */
    )
{
    return get_ldapmessage_controls_ext(pb, ber, controlsp, 0 /* do not ignore criticality */);
}

int
slapi_control_present(LDAPControl **controls, char *oid, struct berval **val, int *iscritical)
{
    int i;

    slapi_log_err(SLAPI_LOG_TRACE, "slapi_control_present",
                  "=> (looking for %s)\n", oid);

    if (val != NULL) {
        *val = NULL;
    }

    if (controls == NULL) {
        slapi_log_err(SLAPI_LOG_TRACE, "slapi_control_present",
                      "<= 0 (NO CONTROLS)\n");
        return (0);
    }

    for (i = 0; controls[i] != NULL; i++) {
        if (strcmp(controls[i]->ldctl_oid, oid) == 0) {
            if (NULL != val) {
                *val = &controls[i]->ldctl_value;
                if (NULL != iscritical) {
                    *iscritical = (int)controls[i]->ldctl_iscritical;
                }
            }
            slapi_log_err(SLAPI_LOG_TRACE, "slapi_control_present",
                          "<= 1 (FOUND)\n");
            return (1);
        }
    }

    slapi_log_err(SLAPI_LOG_TRACE, "slapi_control_present",
                  "<= 0 (NOT FOUND)\n");
    return (0);
}


/*
 * Write sequence of controls in "ctrls" to "ber".
 * Return zero on success and -1 if an error occurs.
 */
int
write_controls(BerElement *ber, LDAPControl **ctrls)
{
    int i;
    unsigned long rc;

    rc = ber_start_seq(ber, LDAP_TAG_CONTROLS);
    if (rc == LBER_ERROR) {
        return (-1);
    }

    /* if the criticality is false, it should be absent from the encoding */
    for (i = 0; ctrls[i] != NULL; ++i) {
        if (ctrls[i]->ldctl_value.bv_val == 0) {
            if (ctrls[i]->ldctl_iscritical) {
                rc = ber_printf(ber, "{sb}", ctrls[i]->ldctl_oid,
                                ctrls[i]->ldctl_iscritical);
            } else {
                rc = ber_printf(ber, "{s}", ctrls[i]->ldctl_oid);
            }
        } else {
            if (ctrls[i]->ldctl_iscritical) {
                rc = ber_printf(ber, "{sbo}", ctrls[i]->ldctl_oid,
                                ctrls[i]->ldctl_iscritical,
                                ctrls[i]->ldctl_value.bv_val,
                                ctrls[i]->ldctl_value.bv_len);
            } else {
                rc = ber_printf(ber, "{so}", ctrls[i]->ldctl_oid,
                                ctrls[i]->ldctl_value.bv_val,
                                ctrls[i]->ldctl_value.bv_len);
            }
        }
        if (rc == LBER_ERROR) {
            return (-1);
        }
    }

    rc = ber_put_seq(ber);
    if (rc == LBER_ERROR) {
        return (-1);
    }

    return (0);
}


/*
 * duplicate "newctrl" and add it to the array of controls "*ctrlsp"
 * note that *ctrlsp may be reset and that it is okay to pass NULL for it.
 * IF copy is true, a copy of the passed in control will be added - copy
 * made with slapi_dup_control - if copy is false, the control
 * will be used directly and may be free'd by ldap_controls_free - so
 * make sure it is ok for the control array to own the pointer you
 * pass in
 */
void
add_control_ext(LDAPControl ***ctrlsp, LDAPControl *newctrl, int copy)
{
    int count;

    if (*ctrlsp == NULL) {
        count = 0;
    } else {
        for (count = 0; (*ctrlsp)[count] != NULL; ++count) {
            ;
        }
    }

    *ctrlsp = (LDAPControl **)slapi_ch_realloc((char *)*ctrlsp,
                                               (count + 2) * sizeof(LDAPControl *));

    if (copy) {
        (*ctrlsp)[count] = slapi_dup_control(newctrl);
    } else {
        (*ctrlsp)[count] = newctrl;
    }
    (*ctrlsp)[++count] = NULL;
}

/*
 * duplicate "newctrl" and add it to the array of controls "*ctrlsp"
 * note that *ctrlsp may be reset and that it is okay to pass NULL for it.
 */
void
add_control(LDAPControl ***ctrlsp, LDAPControl *newctrl)
{
    add_control_ext(ctrlsp, newctrl, 1 /* copy */);
}

void
slapi_add_control_ext(LDAPControl ***ctrlsp, LDAPControl *newctrl, int copy)
{
    add_control_ext(ctrlsp, newctrl, copy);
}

/*
 * return a malloc'd copy of "ctrl"
 */
LDAPControl *
slapi_dup_control(LDAPControl *ctrl)
{
    LDAPControl *rctrl;

    rctrl = (LDAPControl *)slapi_ch_malloc(sizeof(LDAPControl));

    rctrl->ldctl_oid = slapi_ch_strdup(ctrl->ldctl_oid);
    rctrl->ldctl_iscritical = ctrl->ldctl_iscritical;

    if (ctrl->ldctl_value.bv_val == NULL) { /* no value */
        rctrl->ldctl_value.bv_len = 0;
        rctrl->ldctl_value.bv_val = NULL;
    } else if (ctrl->ldctl_value.bv_len <= 0) { /* zero length value */
        rctrl->ldctl_value.bv_len = 0;
        rctrl->ldctl_value.bv_val = slapi_ch_malloc(1);
        rctrl->ldctl_value.bv_val[0] = '\0';
    } else { /* value with content */
        rctrl->ldctl_value.bv_len = ctrl->ldctl_value.bv_len;
        rctrl->ldctl_value.bv_val =
            slapi_ch_malloc(ctrl->ldctl_value.bv_len);
        memcpy(rctrl->ldctl_value.bv_val, ctrl->ldctl_value.bv_val,
               ctrl->ldctl_value.bv_len);
    }

    return (rctrl);
}

void
slapi_add_controls(LDAPControl ***ctrlsp, LDAPControl **newctrls, int copy)
{
    int ii;
    for (ii = 0; newctrls && newctrls[ii]; ++ii) {
        slapi_add_control_ext(ctrlsp, newctrls[ii], copy);
    }
}

int
slapi_build_control(char *oid, BerElement *ber, char iscritical, LDAPControl **ctrlp)
{
    int rc = 0;
    int return_value = LDAP_SUCCESS;
    struct berval *bvp = NULL;

    PR_ASSERT(NULL != oid && NULL != ctrlp);

    if (NULL == ber) {
        bvp = NULL;
    } else {
        /* allocate struct berval with contents of the BER encoding */
        rc = ber_flatten(ber, &bvp);
        if (-1 == rc) {
            return_value = LDAP_NO_MEMORY;
            goto loser;
        }
    }

    /* allocate the new control structure */
    *ctrlp = (LDAPControl *)slapi_ch_calloc(1, sizeof(LDAPControl));

    /* fill in the fields of this new control */
    (*ctrlp)->ldctl_iscritical = iscritical;
    (*ctrlp)->ldctl_oid = slapi_ch_strdup(oid);
    if (NULL == bvp) {
        (*ctrlp)->ldctl_value.bv_len = 0;
        (*ctrlp)->ldctl_value.bv_val = NULL;
    } else {
        (*ctrlp)->ldctl_value = *bvp; /* struct copy */
        ldap_memfree(bvp);            /* free container, but not contents */
        bvp = NULL;
    }

loser:
    return return_value;
}

/*
 * Build an allocated LDAPv3 control from a berval. Returns an LDAP error code.
 */
int
slapi_build_control_from_berval(char *oid, struct berval *bvp, char iscritical, LDAPControl **ctrlp)
{
    int return_value = LDAP_SUCCESS;

    /* allocate the new control structure */
    *ctrlp = (LDAPControl *)slapi_ch_calloc(1, sizeof(LDAPControl));

    /* fill in the fields of this new control */
    (*ctrlp)->ldctl_iscritical = iscritical;
    (*ctrlp)->ldctl_oid = slapi_ch_strdup(oid);
    if (NULL == bvp) {
        (*ctrlp)->ldctl_value.bv_len = 0;
        (*ctrlp)->ldctl_value.bv_val = NULL;
    } else {
        (*ctrlp)->ldctl_value = *bvp; /* struct copy */
    }

    return return_value;
}

/*
 * Parse an LDAP control into its parts
 * The caller must free "value"
 */
void
slapi_parse_control(LDAPControl *ctrl, char **oid, char **value, bool *isCritical)
{
    *isCritical = ctrl->ldctl_iscritical;
    if (ctrl->ldctl_value.bv_len > 0) {
        *value = PL_Base64Encode(ctrl->ldctl_value.bv_val, ctrl->ldctl_value.bv_len, NULL);
    }
    *oid = ctrl->ldctl_oid;
}
