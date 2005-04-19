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
#ifndef BASE_SYSTHR_H
#define BASE_SYSTHR_H

#ifndef NOINTNSAPI
#define INTNSAPI
#endif /* !NOINTNSAPI */

/*
 * systhr.h: Abstracted threading mechanisms
 * 
 * Rob McCool
 */

#ifndef NETSITE_H
#include "netsite.h"
#endif /* !NETSITE_H */

#ifdef THREAD_ANY

/* --- Begin function prototypes --- */

#ifdef INTNSAPI

NSPR_BEGIN_EXTERN_C

#ifdef UnixWare
typedef void(*ArgFn_systhread_start)(void *);
NSAPI_PUBLIC
SYS_THREAD INTsysthread_start( int prio, int stksz, \
                              ArgFn_systhread_start, void *arg);
#else
NSAPI_PUBLIC
SYS_THREAD INTsysthread_start(int prio, int stksz, void (*fn)(void *), void *arg);
#endif

NSAPI_PUBLIC SYS_THREAD INTsysthread_current(void);

NSAPI_PUBLIC void INTsysthread_yield(void);

NSAPI_PUBLIC SYS_THREAD INTsysthread_attach(void);

NSAPI_PUBLIC void INTsysthread_detach(SYS_THREAD thr);

NSAPI_PUBLIC void INTsysthread_terminate(SYS_THREAD thr);

NSAPI_PUBLIC void INTsysthread_sleep(int milliseconds);

NSAPI_PUBLIC void INTsysthread_init(char *name);

NSAPI_PUBLIC void INTsysthread_timerset(int usec);

NSAPI_PUBLIC int INTsysthread_newkey(void);

NSAPI_PUBLIC void *INTsysthread_getdata(int key);

NSAPI_PUBLIC void INTsysthread_setdata(int key, void *data);

NSAPI_PUBLIC 
void INTsysthread_set_default_stacksize(unsigned long size);

NSPR_END_EXTERN_C

/* --- End function prototypes --- */
#define systhread_start INTsysthread_start
#define systhread_current INTsysthread_current
#define systhread_yield INTsysthread_yield
#define systhread_attach INTsysthread_attach
#define systhread_detach INTsysthread_detach
#define systhread_terminate INTsysthread_terminate
#define systhread_sleep INTsysthread_sleep
#define systhread_init INTsysthread_init
#define systhread_timerset INTsysthread_timerset
#define systhread_newkey INTsysthread_newkey
#define systhread_getdata INTsysthread_getdata
#define systhread_setdata INTsysthread_setdata
#define systhread_set_default_stacksize INTsysthread_set_default_stacksize

#endif /* INTNSAPI */

#endif /* THREAD_ANY */

#endif /* !BASE_SYSTHR_H */
