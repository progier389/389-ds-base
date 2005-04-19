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
/* dirlite_strings.h - strings  used for Directory Lite */
#ifndef _DIRLITE_STRINGS_H_
#define _DIRLITE_STRINGS_H_

#define LITE_PRODUCT_NAME "restricted-mode directory"
#define LITE_UPGRADE_BLURB "To gain access to this feature, you must upgrade to the full verson of the directory."

#define LITE_GENERIC_ERR "cannot be configured in the " LITE_PRODUCT_NAME ". " LITE_UPGRADE_BLURB



/* Directory Lite: Error Strings related to configuring replication */
#define LITE_CHANGELOG_DIR_ERR     "Error: changelog cannot be configured in DirectoryLite."
#define LITE_CHANGELOG_SUFFIX_ERR  "Error: changelogsuffix cannot be configured in DirectoryLite."
#define LITE_CHANGELOG_MAXAGE_ERR  "Error: changelogmaxage cannot be configured in DirectoryLite."
#define LITE_CHANGELOG_MAXENTRIES_ERR "Error: changelogmaxentries cannot be configured in DirectoryLite."
#define LITE_REPLICATIONDN_ERR "Error: replicationdn cannot be configured in DirectoryLite."
#define LITE_REPLICATIONPW_ERR "Error: replicationpw cannot be configured in DirectoryLite."



/* Directory Lite: Error Strings related to configurating referrals */
#define LITE_DEFAULT_REFERRAL_ERR "Error: Referrals are disabled in the " LITE_PRODUCT_NAME ", The defaultreferral " LITE_GENERIC_ERR

#define LITE_REFERRAL_MODE_ERR "Error: Referrals are disabled in the " LITE_PRODUCT_NAME ", The referralmode " LITE_GENERIC_ERR

/* Directory Lite: Error Strings related to configuring password policy */
#define LITE_PW_EXP_ERR "Error: password policy is disabled in the " LITE_PRODUCT_NAME ", pw_exp " LITE_GENERIC_ERR

/* all plugins which need to be used for Directory Lite must use this as their vendor string */
#define PLUGIN_MAGIC_VENDOR_STR "Fedora Project"

/* plugins which contain this substring in their pluginid will not be aprroved in DS Lite */
#define LITE_NTSYNCH_PLUGIN_ID_SUBSTR "nt-sync"

/*Directory Lite: Error Strings related to configuring nt synch service */
#define LITE_NTSYNCH_ERR "Error: NT Synch Service " LITE_GENERIC_ERR " nt_synch cannot be enabled."

#define LITE_DISABLED_ATTRS_DN    "cn=attributes,cn=options,cn=features,cn=config"
#define LITE_DISABLED_MODULES_DN  "cn=modules,cn=options,cn=features,cn=config"

#define LITE_REPLICA_ERR "Error: Replication is disabled in the " LITE_PRODUCT_NAME ", replica " LITE_GENERIC_ERR

/*Directory Lite: Error Strings related to configuring maxdescriptors */
#define LITE_MAXDESCRIPTORS_ERR "Warning: The maximum number of concurent connections to the " LITE_PRODUCT_NAME " is 256. Maxdescriptors has a maximum value of 256, setting value for maxdescriptors to 256. To increase the maximum number of concurent connections, you must upgrade to the full version of the directory."
#define SLAPD_LITE_MAXDESCRIPTORS 256

/* on-line backup and restore */
#define LITE_BACKUP_ERR "Error: The " LITE_PRODUCT_NAME " server must be in readonly mode before you can do this operation. You must upgrade to the full version of the directory to be able to perform online backup without first putting the server into readonly mode."

/* Directory Lite: Error string related to enabling third party plugins */
#define LITE_3RD_PARTY_PLUGIN_ERR "Error: Plugins written by third parties are disabled in " LITE_PRODUCT_NAME ". Plugin \"%s\" is disabled. " LITE_UPGRADE_BLURB

#endif /* _DIRLITE_STRINGS_H_ */



