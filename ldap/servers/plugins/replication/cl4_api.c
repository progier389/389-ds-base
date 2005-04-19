/** BEGIN COPYRIGHT BLOCK
 * This Program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 2 of the License.
 * 
 * This Program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this Program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA.
 * 
 * In addition, as a special exception, Red Hat, Inc. gives You the additional
 * right to link the code of this Program with code not covered under the GNU
 * General Public License ("Non-GPL Code") and to distribute linked combinations
 * including the two, subject to the limitations in this paragraph. Non-GPL Code
 * permitted under this exception must only link to the code of this Program
 * through those well defined interfaces identified in the file named EXCEPTION
 * found in the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline functions from
 * the Approved Interfaces without causing the resulting work to be covered by
 * the GNU General Public License. Only Red Hat, Inc. may make changes or
 * additions to the list of Approved Interfaces. You must obey the GNU General
 * Public License in all respects for all of the Program code and other code used
 * in conjunction with the Program except the Non-GPL Code covered by this
 * exception. If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so. If you do not wish to
 * provide this exception without modification, you must delete this exception
 * statement from your version and license this file solely under the GPL without
 * exception. 
 * 
 * 
 * Copyright (C) 2001 Sun Microsystems, Inc. Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/
/* cl4_api.h - implementation of the minimal interface to 4.0 changelog necessary to 
               link 4.0 changelog to 5.0 replication
 */

#include "repl.h"
#include "cl4_api.h"
#include "csnpl.h"
#include "cl4.h"

/*** Data Structures ***/

/* changelog internal data */
typedef struct cl4priv
{
	CSNPL	*csnPL;				/* csn pending list */
	int		regID;				/* csn function registration id */
}CL4Private;

/* callback data to get result of internal operations */
typedef struct cl4ret
{
	int err;			/* error code	*/
	Slapi_Entry *e;		/* target entry	*/
}CL4Ret;

/* Global Data */
static CL4Private s_cl4Desc;	/* represents changelog state */

/*** Helper functions forward declarations ***/
static int _cl4WriteOperation (const slapi_operation_parameters *op); 
static void _cl4AssignCSNCallback (const CSN *csn, void *data);
static void _cl4AbortCSNCallback (const CSN *csn, void *data);
static char* _cl4MakeCSNDN (const CSN* csn);
static int _cl4GetEntry (const CSN *csn, Slapi_Entry **entry);
static void _cl4ResultCallback (int err, void *callback_data);
static int _cl4EntryCallback (Slapi_Entry *e, void *callback_data);
static PRBool _cl4CanAssignChangeNumber (const CSN *csn);
static int _cl4ResolveTargetDN (Slapi_Entry *entry, Slapi_DN **newTargetDN);
static int _cl4GetTargetEntry (Slapi_DN *targetDN, const char *uniqueid, Slapi_Entry **entry);
static int _cl4FindTargetDN (const CSN *csn, const char *uniqueid, 
							 const Slapi_DN *targetSDN, Slapi_DN **newTargetDN);
static int _cl4AssignChangeNumber (changeNumber *cnum);		
static int _cl4UpdateEntry (const CSN *csn, const char *changeType, const Slapi_DN *newTargetDN, changeNumber cnum);

/*** API ***/
int cl4Init ()
{
	s_cl4Desc.csnPL = csnplNew ();
	if (s_cl4Desc.csnPL == NULL)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "cl4Init: failed to create CSN pending list\n");
		return CL4_CSNPL_ERROR;
	}

	s_cl4Desc.regID = csnRegisterNewCSNCb(_cl4AssignCSNCallback, NULL,
										  _cl4AbortCSNCallback, NULL);

	return CL4_SUCCESS;
}

void cl4Cleanup ()
{
	if (s_cl4Desc.regID >= 0)
	{
		csnRemoveNewCSNCb(s_cl4Desc.regID);
		s_cl4Desc.regID = -1;
	}

	if (s_cl4Desc.csnPL == NULL)
		csnplFree (&s_cl4Desc.csnPL);
}

int cl4WriteOperation (const slapi_operation_parameters *op)
{
	int rc;
	ReplicaId rd;

	if (op == NULL || !IsValidOperation (op))
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "cl4WriteEntry: invalid entry\n");
		return CL4_BAD_DATA;
	}
	
	rc = _cl4WriteOperation (op);	
	if (rc != CL4_SUCCESS)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "cl4WriteEntry: failed to write changelog entry\n");
		return rc;
	}

	/* the entry is generated by this server - remove the entry from the pending list */
	rd= csn_get_replicaid(op->csn);
	if (rd == slapi_get_replicaid ())
	{			
		rc = csnplRemove (s_cl4Desc.csnPL, op->csn);

		if (rc != 0)
		{
			slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, 
							"cl4WriteEntry: failed to remove CSN from the pending list\n");
			rc = CL4_CSNPL_ERROR;
		}
	}

	return rc;
}

int cl4ChangeTargetDN (const CSN *csn, const char *newDN)
{
	Slapi_PBlock *pb;
	char *changeEntryDN;
	Slapi_Mods smods;
	int res;

	if (csn == NULL || newDN == NULL)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "cl4ChangeTargetDN: invalid argument\n");
		return CL4_BAD_DATA;
	}

	/* construct dn of the change entry */
	changeEntryDN = _cl4MakeCSNDN (csn);
	if (changeEntryDN == NULL)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, 
						"cl4ChangeTargetDN: failed to construct change entry dn\n");
		return CL4_MEMORY_ERROR;
	}

	pb = slapi_pblock_new ();

	slapi_mods_init(&smods, 1);
	slapi_mods_add(&smods, LDAP_MOD_REPLACE | LDAP_MOD_BVALUES, attr_targetdn, 
				   strlen (newDN), newDN);
	slapi_modify_internal_set_pb(pb, changeEntryDN, slapi_mods_get_ldapmods_byref(&smods), 
								 NULL, NULL, repl_get_plugin_identity(PLUGIN_LEGACY_REPLICATION), 0);
	slapi_modify_internal_pb (pb);

	slapi_mods_done(&smods);
	slapi_ch_free ((void**)&changeEntryDN);
	
	slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &res);
	slapi_pblock_destroy(pb);

	if (res != LDAP_SUCCESS) 
	{
		char s[CSN_STRSIZE];
	    slapi_log_error( SLAPI_LOG_FATAL, repl_plugin_name,
	    "cl4ChangeTargetDN: an error occured while modifying change entry with csn %s: %s. "
	    "Logging of changes is disabled.\n", csn_as_string(csn,PR_FALSE,s), ldap_err2string(res));
	    /* GGOODREPL g_set_repl_backend( NULL ); */
		return CL4_LDAP_ERROR;
	}

	return CL4_SUCCESS;                      
}

void cl4AssignChangeNumbers (time_t when, void *arg)
{
	int rc = CL4_SUCCESS;
	Slapi_Entry *entry;
	CSN *csn = NULL;
	Slapi_DN *newTargetDN;
	changeNumber cnum;
	char *changetype;

	/* we are looping though the entries ready to be commited updating there target dn
	   and assigning change numbers */
	while (_cl4GetEntry (csn, &entry) == CL4_SUCCESS)
	{
		/* ONREPL - I think we need to free previous csn */
		csn = csn_new_by_string(slapi_entry_attr_get_charptr (entry, attr_csn));
		/* all conflicts involving this entry have been resolved */
		if (_cl4CanAssignChangeNumber (csn))
		{
			/* figure out the name of the target entry that corresponds to change csn */
			rc = _cl4ResolveTargetDN (entry, &newTargetDN);
			slapi_entry_free (entry);
			if (rc != CL4_SUCCESS)
			{
				slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "cl4AssignChangeNumbers: failed to resolve target dn\n");
				break;
			}

			_cl4AssignChangeNumber (&cnum);	

			changetype = slapi_entry_attr_get_charptr (entry, attr_changetype);	

			/* update change entry: write change number and remove csn attribute.
			   Note that we leave uniqueid in the entry to avoid an extra update.
			   This is ok since uniqueid is an operational attribute not returned
			   to the client by default. */
			rc = _cl4UpdateEntry (csn, changetype, newTargetDN, cnum);
			if (newTargetDN)
			{
				slapi_sdn_free (&newTargetDN);
			}

			slapi_ch_free ((void**)&changetype);

			if (rc != CL4_SUCCESS)
			{
				slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, 
							    "cl4AssignChangeNumbers: failed to update changelog entry\n");
				break;
			}
		}
		else /* went too far */
		{
			slapi_entry_free (entry);
			break;
		}		
	}
}


/*** Helper Functions ***/

/* adds new change record to 4.0 changelog */
static int _cl4WriteOperation (const slapi_operation_parameters *op)
{
	int rc = CL4_SUCCESS, res;
    char *changeEntryDN, *timeStr;
    Slapi_Entry		*e;
    Slapi_PBlock	*pb = NULL;
	Slapi_Value     *values[3];
	char s[CSN_STRSIZE];
   
    slapi_log_error (SLAPI_LOG_PLUGIN, repl_plugin_name,
	    "_cl4WriteEntry: writing change record with csn %s for dn: \"%s\"\n", 
	    csn_as_string(op->csn,PR_FALSE,s), op->target_address.dn);

	/* create change entry dn */ 
	changeEntryDN = _cl4MakeCSNDN (op->csn);
	if (changeEntryDN == NULL)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, 
						"_cl4WriteEntry: failed to create entry dn\n");
		return CL4_MEMORY_ERROR;
	}

    /*
     * Create the entry struct, and fill in fields common to all types
     * of change records.
     */
    e = slapi_entry_alloc();
	if (e == NULL)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, 
						"_cl4WriteEntry: failed to allocate change entry\n");
		return CL4_MEMORY_ERROR;
	}

    slapi_entry_set_dn(e, slapi_ch_strdup (changeEntryDN));

    /* Set the objectclass attribute */
	values [0] = slapi_value_new (NULL);
	values [1] = slapi_value_new (NULL);
	values [2] = NULL;
    slapi_value_set_string(values[0], "top");
	slapi_value_set_string(values[1], "changelogentry");
    slapi_entry_add_values_sv (e, "objectclass", values);

	/* ONREPL - for now we have to free Slapi_Values since api makes copy;
				this will change when a new set of api is added */
	slapi_value_free (&(values[0]));				
	slapi_value_free (&(values[1]));				

    /* Set the changeNumber attribute */
	/* Need to set this because it is required by schema */
    slapi_entry_attr_set_charptr (e, attr_changenumber, "0");

    /* Set the targetentrydn attribute */
	if (op->operation_type == SLAPI_OPERATION_ADD) /* use raw dn */
		slapi_entry_attr_set_charptr (e, attr_targetdn, slapi_entry_get_dn (op->p.p_add.target_entry));		
	else /* use normolized dn */
		slapi_entry_attr_set_charptr (e, attr_targetdn, op->target_address.dn);

	/* ONREPL - set dbid attribute */		

    /* Set the changeTime attribute */
    timeStr = format_localTime (current_time());
    slapi_entry_attr_set_charptr (e, attr_changetime, timeStr);
    slapi_ch_free((void**)&timeStr);

    /*
     * Finish constructing the entry.  How to do it depends on the type
     * of modification being logged.
     */
    switch (op->operation_type) 
	{
		case SLAPI_OPERATION_ADD:	if (entry2reple(e, op->p.p_add.target_entry) != 0 ) 
									{
										rc = CL4_INTERNAL_ERROR;
										goto done;
									}

									break;

		case SLAPI_OPERATION_MODIFY: if (mods2reple(e, op->p.p_modify.modify_mods) != 0) 
									 {
										rc = CL4_INTERNAL_ERROR;
										goto done;
									 }

									 break;

		case SLAPI_OPERATION_MODDN:	if (modrdn2reple(e, op->p.p_modrdn.modrdn_newrdn, 
									    op->p.p_modrdn.modrdn_deloldrdn, op->p.p_modrdn.modrdn_mods) != 0) 
									{
										rc = CL4_INTERNAL_ERROR;
										goto done;
									}

									break;

		case SLAPI_OPERATION_DELETE: /* Set the changetype attribute */
									 slapi_entry_attr_set_charptr (e, attr_changetype, "delete");
									 break;
    }

	pb = slapi_pblock_new (pb);
	slapi_add_entry_internal_set_pb (pb, e, NULL, repl_get_plugin_identity (PLUGIN_LEGACY_REPLICATION), 0);
	slapi_add_internal_pb (pb);
		
	slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &res);
	slapi_pblock_destroy(pb);
	
	if (res != LDAP_SUCCESS) 
	{
		char s[CSN_STRSIZE];
	    slapi_log_error( SLAPI_LOG_FATAL, repl_plugin_name,
			"_cl4WriteEntry: an error occured while adding change entry with csn %s, dn = %s: %s. "
			"Logging of changes is disabled.\n", csn_as_string(op->csn,PR_FALSE,s), op->target_address.dn, 
			ldap_err2string(res));
	    /* GGOODREPL g_set_repl_backend( NULL ); */
		rc = CL4_LDAP_ERROR;
	}
 
done:
	if (changeEntryDN)   
		slapi_ch_free((void **) &changeEntryDN);

	return rc;
}

static void _cl4AssignCSNCallback (const CSN *csn, void *data)
{
	int rc;

	if (csn == NULL)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "_cl4AssignCSNCallback: null csn\n");
		return;
	}

	rc = csnplInsert (s_cl4Desc.csnPL, csn);

	if (rc == -1)
	{
		char s[CSN_STRSIZE];
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, 
				"_cl4AssignCSNCallback: failed to insert csn %s to the pending list\n",
				csn_as_string(csn,PR_FALSE,s));
	}
}

static void _cl4AbortCSNCallback (const CSN *csn, void *data)
{
	int rc;

	if (csn == NULL)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "_cl4AbortCSNCallback: null csn\n");
		return;
	}

	rc = csnplRemove (s_cl4Desc.csnPL, csn);
	if (rc == -1)
	{
		char s[CSN_STRSIZE];
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, 
				"_cl4AbortCSNCallback: failed to remove csn %s from the pending list\n",
				csn_as_string(csn,PR_FALSE,s));		
	}
}

/* initial dn format: csn=<csn>,<changelog suffix>. For instance, csn=013744022939465,cn=changelog4 */
static char* _cl4MakeCSNDN (const CSN* csn)
{
	char *pat, *edn;
	char *suffix = changelog4_get_suffix ();
	char s[CSN_STRSIZE];

	if (suffix == NULL)
		return NULL;

	/* Construct the dn of this change record */
    edn = slapi_ch_smprintf("%s=%s,%s", attr_csn, csn_as_string(csn,PR_FALSE,s), suffix);
	slapi_ch_free ((void **)&suffix);

	return edn;
}

static int _cl4GetEntry (const CSN *csn, Slapi_Entry **entry)
{
	int rc;
	char *suffix = changelog4_get_suffix ();
	int type;
	const char *value;
	CL4Ret ret;
	char s[CSN_STRSIZE];		

	if (csn == NULL)	/* entry with smallest csn */
	{
		type = SLAPI_SEQ_FIRST;	
		value = NULL;
	}
	else /* entry with next csn */
	{
		type = SLAPI_SEQ_NEXT;	
		value = csn_as_string(csn,PR_FALSE,s);
	}

	rc = slapi_seq_callback(suffix, type, attr_csn, (char*)value, NULL, 0, &ret, NULL,
							_cl4ResultCallback, _cl4EntryCallback, NULL);
	slapi_ch_free ((void**)&suffix);

	if (rc != 0 || ret.err != 0)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "_cl4GetEntry: failed to get next changelog entry\n");
		return CL4_INTERNAL_ERROR;
	}

	*entry = ret.e;
	return CL4_SUCCESS;                   	
}

static void _cl4ResultCallback (int err, void *callback_data)
{
	CL4Ret *ret = (CL4Ret *)callback_data;

	if (ret)
	{
		ret->err = err;
	}	
}

static int _cl4EntryCallback (Slapi_Entry *e, void *callback_data)
{
	CL4Ret *ret = (CL4Ret *)callback_data;

	if (ret)
	{
		ret->e = slapi_entry_dup (e);
	}

	return 0;	
}

static PRBool _cl4CanAssignChangeNumber (const CSN *csn)
{
	CSN *commitCSN = NULL;

	/* th CSN is withtin region that can be commited */
	if (csn && csn_compare(csn, commitCSN) < 0)
		return PR_TRUE;

	return PR_FALSE;
}

/* ONREPL - describe algorithm */
static int _cl4ResolveTargetDN (Slapi_Entry *entry, Slapi_DN **newTargetDN)
{
	int rc;
	char *csnStr = slapi_entry_attr_get_charptr (entry, attr_csn);
	char *targetdn = slapi_entry_attr_get_charptr (entry, attr_targetdn);
	const char *uniqueid = slapi_entry_get_uniqueid (entry);
	char *changetype = slapi_entry_attr_get_charptr (entry, attr_changetype);
	CSN *csn = csn_new_by_string (csnStr);
	Slapi_Entry *targetEntry = NULL;
	const Slapi_DN *teSDN;
	Slapi_DN *targetSDN;
	const CSN *teDNCSN = NULL;
	
	*newTargetDN = NULL;

	targetSDN = slapi_sdn_new();
	if (strcasecmp (changetype, "add") == 0) /* this is add operation - we have rawdn */
		slapi_sdn_set_dn_byref (targetSDN, targetdn);	
	else
		slapi_sdn_set_ndn_byref (targetSDN, targetdn);

	/* read the entry to which the change was applied */
	rc = _cl4GetTargetEntry (targetSDN, uniqueid, &targetEntry);
	if (rc != CL4_SUCCESS)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "_cl4ResolveTargetDN: failed to get target entry\n");
		goto done;
	}

	teDNCSN = entry_get_dncsn(targetEntry);
	if (teDNCSN == NULL)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "_cl4ResolveTargetDN: failed to get target entry dn\n");
		rc = CL4_BAD_FORMAT;
		goto done;
	}
	
	if (csn_compare(teDNCSN, csn) <= 0)
	{
		/* the change entry target dn should be the same as target entry dn */
		teSDN = slapi_entry_get_sdn_const(targetEntry);

		/* target dn of change entry is not the same as dn of the target entry - update */
		if (slapi_sdn_compare (teSDN, targetSDN) != 0)
		{
			*newTargetDN = slapi_sdn_dup (targetSDN);	
		}
	}
	else /* the target entry was renamed since this change occur - find the right target dn */
	{
		rc = _cl4FindTargetDN (csn, uniqueid, targetSDN, newTargetDN);
	}

done:;
	if (csnStr)
		slapi_ch_free ((void**)&csnStr);
	
	if (targetdn)
		slapi_ch_free ((void**)&targetdn);		

	if (uniqueid)
		slapi_ch_free ((void**)&uniqueid);

	if (changetype)
		slapi_ch_free ((void**)&changetype);
	
	if (targetEntry)
		slapi_entry_free (targetEntry);

	if (targetSDN)
		slapi_sdn_free (&targetSDN);

	return rc;
}

static int _cl4GetTargetEntry (Slapi_DN *sdn, const char *uniqueid, Slapi_Entry **entry)
{
	Slapi_PBlock *pb;
	char filter [128];
	int res, rc = CL4_SUCCESS;
	Slapi_Entry **entries = NULL;

	/* read corresponding database entry based on its uniqueid */
	PR_snprintf (filter, sizeof(filter), "uniqueid=%s", uniqueid);	
	pb = slapi_pblock_new ();
	slapi_search_internal_set_pb (pb, (char*)slapi_sdn_get_ndn(sdn), LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL,
								  repl_get_plugin_identity (PLUGIN_LEGACY_REPLICATION), 0);
	slapi_search_internal_pb (pb);

	if (pb == NULL)
	{
		rc = CL4_LDAP_ERROR;
		goto done;
	}

	slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &res);
	if (res == LDAP_NO_SUCH_OBJECT)	/* entry not found */
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "_cl4GetTargetEntry: entry (%s) not found\n", 
						slapi_sdn_get_ndn(sdn));
		rc = CL4_NOT_FOUND;
		goto done;
	}

	if (res != LDAP_SUCCESS) 
	{
	    slapi_log_error( SLAPI_LOG_FATAL, repl_plugin_name,
	    "_cl4ResolveTargetDN: an error occured while searching for directory entry with uniqueid %s: %s. "
	    "Logging of changes is disabled.\n", uniqueid, ldap_err2string(res));
	    /* GGOODREPL g_set_repl_backend( NULL ); */
		rc = CL4_LDAP_ERROR;
		goto done;
	}
	
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
	if (entries == NULL || entries [0] == NULL)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "_cl4GetTargetEntry: entry (%s) not found\n", 
						slapi_sdn_get_ndn(sdn));
		rc = CL4_NOT_FOUND;
		goto done;	
	}

	*entry = slapi_entry_dup (entries[0]);

done:
	if (pb)
	{
		slapi_free_search_results_internal(pb);
		slapi_pblock_destroy (pb);
	}
	
	return rc;
}

static int _cl4FindTargetDN (const CSN *csn, const char *uniqueid, 
							 const Slapi_DN *targetSDN, Slapi_DN **newTargetDN)
{
	int rc = CL4_SUCCESS;
	int res, i;
	Slapi_PBlock *pb;
	char *suffix = changelog4_get_suffix ();
	char filter [128];
	Slapi_Entry **entries;
	int minIndex = 0;
	CSN *minCSN = NULL, *curCSN;
	char *curType;	
	const Slapi_DN	*sdn;
	char s[CSN_STRSIZE];		

	*newTargetDN = NULL;

	/* Look for all modifications to the target entry with csn larger than 
	   this csn. We are only interested in rename operations, but change type
       is currently not indexed */
	PR_snprintf (filter, 128, "&(uniqueid=%s)(csn>%s)", uniqueid, csn_as_string(csn,PR_FALSE,s));
	pb = slapi_pblock_new ();
	slapi_search_internal_set_pb (pb, suffix, LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL,
								  repl_get_plugin_identity (PLUGIN_LEGACY_REPLICATION), 0);
	slapi_search_internal_pb (pb);
	slapi_ch_free ((void**)&suffix);
	if (pb == NULL)
	{
		rc = CL4_LDAP_ERROR;
		goto done;
	}

	slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &res);
	if (res == LDAP_NO_SUCH_OBJECT)	/* entry not found */
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "_cl4FindTargetDN: no entries much filter (%s)\n",
						filter);
		rc = CL4_NOT_FOUND;
		goto done;
	}

	if (res != LDAP_SUCCESS) 
	{
	    slapi_log_error( SLAPI_LOG_FATAL, repl_plugin_name,
	    "_cl4ResolveTargetDN: an error occured while searching change entries matching filter %s: %s. "
	    "Logging of changes is disabled.\n", filter, ldap_err2string(res));
	    /* GGOODREPL g_set_repl_backend( NULL ); */
		rc = CL4_LDAP_ERROR;
		goto done;
	}

	slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
	if (entries == NULL)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "_cl4FindTargetDN: no entries much filter (%s)\n",
						filter);
		rc = CL4_NOT_FOUND;
		goto done;	
	}

	i = 0;

	/* find rename operation with smallest csn - its target dn should be the name
	   of our change entry */
	while (entries[i])
	{
		curType = slapi_entry_attr_get_charptr (entries[i], attr_changetype);
		if (curType && strcasecmp (curType, "modrdn") == 0)
		{
			curCSN = csn_new_by_string (slapi_entry_attr_get_charptr (entries[i], attr_csn));
			if (minCSN == NULL || csn_compare (curCSN, minCSN) < 0)
			{
				minCSN = curCSN;
				minIndex = i;
			}
		}

		if (curType)
			slapi_ch_free ((void**)&curType);
		
		i ++;
	}

	if (curCSN == NULL)
	{
		rc = CL4_NOT_FOUND;
		goto done;
	}

	/* update targetDN of our entry if necessary */
	sdn = slapi_entry_get_sdn_const(entries[minIndex]);

	/* target dn does not match to renaming operation - rename change entry */
	if (slapi_sdn_compare (sdn, targetSDN) != 0)
		*newTargetDN = slapi_sdn_dup (sdn);

done:
	if (pb)
	{
		slapi_free_search_results_internal(pb);
		slapi_pblock_destroy (pb);
	}
	
	return rc;
}

static int _cl4AssignChangeNumber (changeNumber *cnum)
{
	*cnum = ldapi_assign_changenumber();
	return CL4_SUCCESS;
}

static int _cl4UpdateEntry (const CSN *csn, const char *changeType, 
						    const Slapi_DN *newDN, changeNumber cnum)
{	 
	Slapi_PBlock *pb;
	char *dn;
	const char *dnTemp;
	int res;
	Slapi_Mods smods;
	char cnumbuf[32];

	if (csn == NULL || changeType == NULL)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "_cl4UpdateEntry: invalid argument\n");
		return CL4_BAD_DATA;
	}

	dn = _cl4MakeCSNDN (csn);
	if (dn == NULL)
	{
		slapi_log_error(SLAPI_LOG_FATAL, repl_plugin_name, "_cl4UpdateEntry: failed to create entry dn\n");
		return CL4_MEMORY_ERROR;
	}

	slapi_mods_init(&smods, 2);
	if (newDN)
	{
		if (strcasecmp (changeType, "add") == 0)
			dnTemp = slapi_sdn_get_dn (newDN);
		else
			dnTemp = slapi_sdn_get_ndn (newDN);
			
		slapi_mods_add(&smods, LDAP_MOD_REPLACE | LDAP_MOD_BVALUES, attr_targetdn, 
					   strlen (dnTemp), dnTemp);
	}
	/* Set the changeNumber attribute */
    sprintf(cnumbuf, "%lu", cnum);
    slapi_mods_add (&smods, LDAP_MOD_REPLACE | LDAP_MOD_BVALUES, attr_changenumber,
					strlen (cnumbuf), cnumbuf);		 
	pb = slapi_pblock_new ();
	slapi_modify_internal_set_pb (pb, dn, slapi_mods_get_ldapmods_byref(&smods), NULL, NULL, 
								  repl_get_plugin_identity (PLUGIN_LEGACY_REPLICATION), 0);
	slapi_modify_internal_pb (pb);
	slapi_mods_done(&smods);	
	slapi_ch_free ((void**)&dn);

	if (pb == NULL)
	{
		return CL4_LDAP_ERROR;
	}
	
	slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &res);
	slapi_pblock_destroy(pb);
	if (res != LDAP_SUCCESS) 
	{
		char s[CSN_STRSIZE];		
	    slapi_log_error( SLAPI_LOG_FATAL, repl_plugin_name,
	    "cl4ChangeTargetDN: an error occured while modifying change entry with csn %s: %s. "
	    "Logging of changes is disabled.\n", csn_as_string(csn,PR_FALSE,s), ldap_err2string(res));
	    /* GGOODREPL g_set_repl_backend( NULL ); */
		return CL4_LDAP_ERROR;
	}

	if ( ldapi_get_first_changenumber() == (changeNumber) 0L ) 
	{
		ldapi_set_first_changenumber( cnum );
	}

	ldapi_commit_changenumber(cnum);
	return CL4_SUCCESS;	
}
