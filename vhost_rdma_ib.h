/*
 * Vhost-user RDMA device demo: ib ops
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

#ifndef __VHOST_RDMA_IB_H__
#define __VHOST_RDMA_IB_H__

#include <rte_spinlock.h>

#include "vhost_rdma.h"

struct vhost_rdma_pd {
	uint32_t pdn;
};

enum vhost_rdma_mr_type {
	VHOST_MR_TYPE_NONE,
	VHOST_MR_TYPE_DMA,
	VHOST_MR_TYPE_MR,
};

struct vhost_rdma_mr {
	struct vhost_rdma_pd *pd;
	enum vhost_rdma_mr_type	type;
	uint64_t	va;
	uint64_t	iova;
	size_t		length;
	uint32_t	offset;
	int			access;

	uint32_t	lkey;
	uint32_t	rkey;

	// int			page_shift;
	// int			page_mask;
	// int			map_shift;
	// int			map_mask;

	// uint32_t	num_buf;
	// uint32_t	nbuf;

	// uint32_t	max_buf;
	// uint32_t	num_map;

	// struct rxe_map		**map;
};

struct vhost_rdma_cq {
	struct vhost_queue *vq;
	rte_spinlock_t		cq_lock;
	uint8_t			notify;
	bool			is_dying;
};

void vhost_rdma_handle_ctrl(void* arg);
void vhost_rdma_init_ib(struct vhost_rdma_dev *dev);
void vhost_rdma_destroy_ib(struct vhost_rdma_dev *dev);

#endif
