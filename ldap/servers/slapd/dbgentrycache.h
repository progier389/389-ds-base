/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2023 Red Hat, Inc.
 * All rights reserved.
 *
 * License: GPL (version 3 or any later version).
 * See LICENSE for details.
 * END COPYRIGHT BLOCK **/
void dbgec_start(void *addr);
void dbgec_stop(void *addr);
void dbgec_add_entry(void *addr);
void dbgec_rem_entry(void *addr);
int dbgec_init();
void dbgec_check_absence(void *addr);
struct cache;
void dbgec_store_cache_info(struct cache *cache, int type);

