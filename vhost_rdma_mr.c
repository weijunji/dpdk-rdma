/*
 * Vhost-user RDMA device demo: memory region
 *
 * Copyright (C) 2021 Junji Wei Bytedance Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <rte_random.h>
#include <rte_malloc.h>

#include "vhost_rdma.h"
#include "vhost_rdma_ib.h"
#include "vhost_rdma_loc.h"

uint8_t
vhost_rdma_get_next_key(uint32_t last_key)
{
	uint8_t key;

	do {
		key = rte_rand();
	} while (key == last_key);

	return key;
}

#define IB_ACCESS_REMOTE	(IBV_ACCESS_REMOTE_READ		\
				| IBV_ACCESS_REMOTE_WRITE	\
				| IBV_ACCESS_REMOTE_ATOMIC)

void
vhost_rdma_mr_init_key(struct vhost_rdma_mr *mr, uint32_t mrn)
{
	uint32_t lkey = mrn << 8 | vhost_rdma_get_next_key(-1);
	uint32_t rkey = (mr->access & IB_ACCESS_REMOTE) ? lkey : 0;

	mr->lkey = lkey;
	mr->rkey = rkey;
}

static __rte_always_inline uint32_t
get_num_l2_pages(uint32_t npages)
{
	return npages == 0 ? 0 : (npages - 1) / 512 + 1;
}

uint64_t**
vhost_rdma_alloc_page_tbl(uint32_t npages)
{
	uint32_t nl2 = get_num_l2_pages(npages);
	uint32_t i;
	uint64_t** l1;

	l1 = rte_zmalloc("page_tbl", TARGET_PAGE_SIZE, 4096);
	for (i = 0; i < nl2; i++) {
		l1[i] = rte_zmalloc("page_tbl_l2", TARGET_PAGE_SIZE, 4096);
	}

	return l1;
}

void
vhost_rdma_destroy_page_tbl(uint64_t **page_tbl, uint32_t npages)
{
	uint32_t nl2 = get_num_l2_pages(npages);
	uint32_t i;

	for (i = 0; i < nl2; i++) {
		rte_free(page_tbl[i]);
	}
	rte_free(page_tbl);
}

void
vhost_rdma_map_pages(struct rte_vhost_memory *mem, uint64_t** page_tbl,
					uint64_t dma_pages, uint32_t npages)
{
	uint32_t nl2 = get_num_l2_pages(npages);
	uint64_t *l1_addr, *l2_addr;
	uint64_t len = TARGET_PAGE_SIZE;
	uint32_t i, j, l2_npages;

	l1_addr = (uint64_t*)gpa_to_vva(mem, dma_pages, &len);
	for (i = 0; i < nl2; i++) {
		l2_addr = (uint64_t*)gpa_to_vva(mem, l1_addr[i], &len);
		l2_npages = npages < 512 ? npages : 512;
		for (j = 0; j < l2_npages; j++) {
			page_tbl[i][j] = (uint64_t)gpa_to_vva(mem, l2_addr[j], &len);
		}
		npages -= l2_npages;
	}
}
