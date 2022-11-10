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



#define _GNU_SOURCE 1

#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#undef CTIME

#include "slap.h"
#include "slapi-plugin.h"
#include "slapi-private.h"

#define ABORT() {   slapi_log_err(SLAPI_LOG_ERR, (char*)__func__, "%s[%d]: ABORT\n", __FILE__, __LINE__); \
                    slapi_log_backtrace(SLAPI_LOG_ERR); \
                    *(char*)23=1; }

/* From back-ldbm.h */
/* type to set ep_type */
#define CACHE_TYPE_ENTRY 0
#define CACHE_TYPE_DN    1

#define HASH_NEXT(ht, entry) (*(void **)((char *)(entry) + (ht)->offset))


typedef u_int32_t ID;

typedef int (*HashTestFn)(const void *, const void *);
typedef unsigned long (*HashFn)(const void *, size_t);
typedef struct
{
    u_long offset;     /* offset of linkage info in user struct */
    u_long size;       /* members in array below */
    HashFn hashfn;     /* compute a hash value on a key */
    HashTestFn testfn; /* function to test if two entries are equal */
    void *slot[1];     /* actually much bigger */
} Hashtable;

struct backcommon
{
    int32_t ep_type;                /* to distinguish backdn from backentry */
    struct backcommon *ep_lrunext;  /* for the cache */
    struct backcommon *ep_lruprev;  /* for the cache */
    ID ep_id;                       /* entry id */
    uint8_t ep_state;               /* state in the cache */
#define ENTRY_STATE_DELETED    0x1  /* entry is marked as deleted */
#define ENTRY_STATE_CREATING   0x2  /* entry is being created; don't touch it */
#define ENTRY_STATE_NOTINCACHE 0x4  /* cache_add failed; not in the cache */
#define ENTRY_STATE_INVALID    0x8  /* cache entry is invalid and needs to be removed */
    int32_t ep_refcnt;              /* entry reference cnt */
    size_t ep_size;                 /* for cache tracking */
    struct timespec ep_create_time; /* the time the entry was added to the cache */
};

struct cache
{
    uint64_t c_maxsize;       /* max size in bytes */
    Slapi_Counter *c_cursize; /* size in bytes */
    int64_t c_maxentries;     /* max entries allowed (-1: no limit) */
    uint64_t c_curentries;    /* current # entries in cache */
    Hashtable *c_dntable;
    Hashtable *c_idtable;
#ifdef UUIDCACHE_ON
    Hashtable *c_uuidtable;
#endif
    Slapi_Counter *c_hits; /* for analysis of hits/misses */
    Slapi_Counter *c_tries;
    struct backcommon *c_lruhead; /* add entries here */
    struct backcommon *c_lrutail; /* remove entries here */
    PRMonitor *c_mutex;           /* lock for cache operations */
    PRLock *c_emutexalloc_mutex;
};


struct cache *_cache = NULL;


/*
 * Must be build with:
 * gcc -g -D_GNU_SOURCE=1    watchpoint.c   -o watchpoint
 *
 * Must be run as root or having done (as root):
 *  echo 1 > /proc/sys/kernel/perf_event_paranoid
 * To reset the default perf_event_paranoid value:
 *  echo 2 > /proc/sys/kernel/perf_event_paranoid

 * beware with ns-slapd (setuid cause trouble - better run
 *  the server directly in debug mode rather than in daemon mode)
 *
 *
 */


int initwatchpoint()
{
    int rc = -1;
    /* Enable trace of setuid process */
    int fd=open("/proc/sys/kernel/perf_event_paranoid",1);
    rc = write(fd,"1\n", 2);
    close(fd);
    return rc > 0 ? 0 : -1;
}


/* Set a hardware breakpoint on write access that generates a SIGSEGV
 * len must be 1,2,4,8
 * Ths function set process wide watchpoint
 *   On x86_64 at most 4 watchpoints could be set on a given process
 *  ( If need it is also posssible to have thread local watchpointsA
 *     by replacing F_OWNER_PID by F_OWNER_TID and getpid by gettid
 *     In that case the limit become 4 watchpoints per threads)
 * Return code: <0 : error
 *              >=0 : file descriptor. (closing it unset the watchpoint)
 *
 * Thanks to https://gist.github.com/jld/5d292c2c48eb07980562
 *  that explained me how to use perf_event to set hardware breakpoint
 */
int setwatchpoint(volatile void *addr, int len)
{
	struct perf_event_attr pea = {0};
	struct f_owner_ex owner = {0};
	int fd = -1;
    int rc = 0;
    int tst = 0;

#define TST(v) { tst--; if (!rc && (v) < 0) { rc = tst; }}

	pea.size = sizeof(pea);
	pea.type = PERF_TYPE_BREAKPOINT;
	pea.bp_type = HW_BREAKPOINT_W;
	pea.bp_addr = (uint64_t) addr;
	pea.bp_len = len;
	pea.sample_period = 1;
	pea.precise_ip = 2; // synchronous delivery
	pea.wakeup_events = 1;

    /* perf_event_open syscall (see man perf_event_open) */
	fd = syscall(__NR_perf_event_open, &pea, 0, -1, -1, PERF_FLAG_FD_CLOEXEC|PERF_FLAG_FD_NO_GROUP);
	TST(fd);
	TST(fcntl(fd, F_SETSIG, SIGSEGV));
    /* Trap all threads */
	owner.type = F_OWNER_PID;
	owner.pid = getpid();
	TST(fcntl(fd, F_SETOWN_EX, &owner));
	TST(fcntl(fd, F_SETFL, O_ASYNC));
    if (rc < -1) {
        close(fd);
    } else {
        rc = fd;
    }
	return rc;
}

int enablewatchpoint(int fd)
{
    return ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
}

int disablewatchpoint(int fd)
{
    return ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
}

int unsetwatchpoint(int fd)
{
    disablewatchpoint(fd);
    return close(fd);
}


#if 0
int main()
{
    volatile long buff[256];
    int wp;
	int c;

    wp = setwatchpoint(&buff['a'], sizeof(buff['a']));
    if (wp<0) {
        fprintf(stderr,"Failed to set watchpoint. rc=%d\n",wp);
		return -1;
	}
    printf("'a' test the watchpoint\n");
    printf("'d' disable the watchpoint\n");
    printf("'e' enable enable the watchpoint\n");
    printf("'q' quit\n");
    disablewatchpoint(wp);
    printf("watchpoint is disabled\n");
    printf("beware: this test programm does not unset tty canonical mode so you had better type return after typing a letter ...\n");
	while ((c = getchar()) != EOF) {
        buff[c] = 0;
		switch (c) {
			case 'd':
				disablewatchpoint(wp);
                printf("disabling watchpoint: 'a' should not SIGSEGV\n");
				break;
			case 'e':
				enablewatchpoint(wp);
                printf("enabling watchpoint: 'a' should SIGSEGV\n");
				break;
			case 'q':
                unsetwatchpoint(wp);
				exit(0);
        }
    }
    unsetwatchpoint(wp);
	return 0;
}
#endif

typedef struct {
    void *addr;
    int fd;
    int count;
    void *next;
} event_t;

static event_t evlist = {0};

/* Find the adress in which the event is stored (or should be added */
event_t **ev_find(void *addr)
{
    event_t **pt = (event_t**)&evlist.next;
	while (*pt && (*pt)->addr != addr) {
        pt =  (event_t**)&(*pt)->next;
    }
    return pt;
}

void dbgec_start(void *addr)
{
#if USE_WATCHPOINT
    int fd;
    event_t **pt = ev_find(addr);
    event_t *e = *pt;
    if (e) {
        slapi_log_err(SLAPI_LOG_ERR, "dbgec_start", "dbgentrycache.c[%d]: Trying to add again an existing watchpoint on address %p\n", __LINE__, addr);
        e->count++;
        return;
    }
    fd = setwatchpoint(addr, 8);
    *pt = e = (event_t *)slapi_ch_calloc(1, sizeof (event_t));
    e->addr = addr;
    e->fd = fd;
    e->count = 1;
    e->next = NULL;
    evlist.next = NULL;
    if (fd>0) {
        slapi_log_err(SLAPI_LOG_ERR, "dbgec_start", "dbgentrycache.c[%d]: SET BREAKPOINT %p: SUCCESS fd=%d\n", __LINE__, addr, fd);
    } else {
        slapi_log_err(SLAPI_LOG_ERR, "dbgec_start", "dbgentrycache.c[%d]: SET BREAKPOINT %p FAILED errno=%d %s\n", __LINE__, addr, errno, strerror(errno));
    }
#endif
}

void dbgec_stop(void *addr)
{
#if USE_WATCHPOINT
    event_t **pt = ev_find(addr);
    event_t *e = *pt;
    if (! e) {
        return;
    }
    e->count--;
    if (e->count) {
        slapi_log_err(SLAPI_LOG_ERR, "dbgec_stop", "dbgentrycache.c[%d]: DECREASING BREAKPOINT %p COUNT\n", __LINE__, addr);
        return;
    }
    slapi_log_err(SLAPI_LOG_ERR, "dbgec_stop", "dbgentrycache.c[%d]: REMOVING BREAKPOINT %p\n", __LINE__, addr);
    *pt = e->next;
    disablewatchpoint(e->fd);
    unsetwatchpoint(e->fd);
    slapi_ch_free((void**)&e);
#endif
}

static void check(Hashtable *ht, void *addr)
{
    if (ht) {
        for (size_t i = 0; i < ht->size; i++) {
            struct backcommon *e = ht->slot[i];
            while (e) {
                if (e == addr) ABORT();
                e = HASH_NEXT(ht, e);
            }
        }
    }
}

void dbgec_store_cache_info(struct cache *cache, int type)
{
    if (type == CACHE_TYPE_ENTRY) {
        /* Only a single cache is supported */
        if (_cache && cache && _cache != cache) ABORT();
        _cache = cache;
    }
}

#if 0
#define HTSZ 65521  /* Should be a prime number */
#define HTNS(s) &_ht[(((s)-_ht)+100) % HTSZ]  /* Next slot */

struct hitem {
    struct hitem *next;
    struct hitem *first;
    void *addr;
};

struct hitem _ht[HTSZ];

int _get_hash(void *addr)
{
    uint64_t h = (uint64_t) addr;
    h /= sizeof (struct backcommon);
    h ^= h >> 10;
    h ^= h >> 20;
    h ^= h >> 30;
    return (int) (h % HTSZ);
}

/* return is the found slot (return->addr == addr) or NULL
 * first is the first slot of slot list 
 * last is the last slot of slot list (may be NULL if first->first is NULL)
 */
struct hitem *_search(void *addr, struct hitem **first, struct hitem **last)
{
    struct hitem *p = &_ht[_get_hash(addr)];
    struct hitem *l = NULL;
    *first = p;
    if (p->first) {
        l = p = p->first;
    }
    while (p && p->addr != addr) {
        l = p;
        p = p->next;
    }
    *last = l;
    return p;
}

void dbgec_add_entry(void *addr)
{
    struct hitem *first = NULL;  /* First slot */
    struct hitem *last = NULL;
    struct hitem *p = _search(addr, &first, &last);  /* Last slot of the linked list */
    if (!p) {
        /* addr not in htable, lets find a free slot */
        p = last ? HTNS(last) : first;
        while (p->addr) {
            p = HTNS(p);
            if (p == first) {
                /* Hash table is full */
                ABORT();
            }
        }
        /* Got a free slot, lets fill it and link it */
        p->addr = addr;
        p->next = NULL;
        if (!first->first) {
            first->first = p;
        } else {
            last->next = p;
        }
    }
}

void dbgec_rem_entry(void *addr)
{
    struct hitem *first = NULL;  /* First slot */
    struct hitem *last = NULL;
    struct hitem *p = _search(addr, &first, &last);  /* Last slot of the linked list */
    if (p) {
        /* addr not in htable, lets unlink it and clear it */
        if (first->first == p) {
            first->first = p->next;
        } else {
            last->next = p->next;
        }
        p->addr = NULL;
        p->next = NULL;
    }
}

void dbgec_check_absence(void *addr)
{
#if 0
    if (_cache) {
        check(_cache->c_dntable, addr);
        check(_cache->c_idtable, addr);
    }
#endif
    if (addr) {
        struct hitem *first = NULL;  /* First slot */
        struct hitem *last = NULL;
        struct hitem *p = _search(addr, &first, &last);
        if (p) ABORT();
    }
}
#else
#define BTBITS  (1L<<32)
#define SHIFT_PER_INT 5
#define MASK_BITS_SHIFT_PER_INT  ((1<<SHIFT_PER_INT)-1)
#define BT_NB_INTS (BTBITS >> SHIFT_PER_INT)

typedef struct {
    size_t index;
    uint32_t mask;
} btidx_t;

int _bt[BT_NB_INTS];

static inline btidx_t _getidx(void *addr)
{
    btidx_t idx;
    uint64_t v = (uint64_t) addr;
    /* Tweak a bit the address as the heap contains addreesses like:
       0x60b00008b520
       0x71b00008b520
       0x6090000e4eb0
       So bits 32-36 seems always 0 but bits 37-42 matters 
       So lets shift the high bits and as we divide the address
       the struct size (i.e 64) they will be significant.
     */
    v = (v & 0xFFFFFFFFL) | ( (v & 0x03F000000000L) >> 4);
    v /= sizeof (struct backcommon);  /* sizeof (struct backcommon) is 64 */

    idx.mask = 1UL << (v & MASK_BITS_SHIFT_PER_INT);
    v = (v >> SHIFT_PER_INT) & (BT_NB_INTS-1);
    idx.index = (uint32) v;
    return idx;
}

void dbgec_add_entry(void *addr)
{
    btidx_t idx = _getidx(addr);
    _bt[idx.index] |= idx.mask;
}

void dbgec_rem_entry(void *addr)
{
    btidx_t idx = _getidx(addr);
    _bt[idx.index] &= ~idx.mask;
}

void dbgec_check_absence(void *addr)
{
    static int indbg = 0;
    if (indbg) return;
    if (addr) {
        btidx_t idx = _getidx(addr);
        if (_bt[idx.index] & idx.mask) {
            indbg++;
            slapi_log_err(SLAPI_LOG_ERR, (char*)__func__, "Freeing address %p that is still in cache.\n", addr);
            ABORT();
        }
    }
}
#endif


/* Return 0 to perform the setuid() or return !0 to bypass it */
int dbgec_init()
{
#if USE_WATCHPOINT
    if (initwatchpoint()) {
        slapi_log_err(SLAPI_LOG_WARNING, "dbgec_init", 
                      "dbgentrycache.c[%d]: Failed to change /proc/sys/kernel/perf_event_paranoid ==> bypassing setuid() and running as root", __LINE__); 
        return 1
    }
#endif
    return 0;
}
