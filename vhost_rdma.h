/*
 * Vhost-user RDMA device demo: rdma device
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

#ifndef __VHOST_RDMA_H__
#define __VHOST_RDMA_H__

#include <rte_log.h>
#include <rte_vhost.h>
#include <rte_interrupts.h>

#include "virtio_rdma.h"

#define RTE_LOGTYPE_RDMA RTE_LOGTYPE_USER2

#define RDMA_LOG_DEBUG(f, ...) RTE_LOG(DEBUG, RDMA, f "\n", ##__VA_ARGS__)
#define RDMA_LOG_INFO(f, ...) RTE_LOG(INFO, RDMA, f "\n", ##__VA_ARGS__)
#define RDMA_LOG_ERR(f, ...) RTE_LOG(ERR, RDMA, f "\n", ##__VA_ARGS__)

#define ROCE_V2_UDP_DPORT 4791

#define NUM_OF_RDMA_QUEUES 256

#define VHOST_RDMA_FEATURE ((1ULL << VIRTIO_RING_F_EVENT_IDX) | \
	(1ULL << VIRTIO_F_VERSION_1) |\
	(1ULL << VIRTIO_RING_F_INDIRECT_DESC) | \
	(1ULL << VHOST_USER_F_PROTOCOL_FEATURES))
// TODO: rdma features

struct vhost_rdma_queue {
	struct rte_vhost_vring vring;

	uint16_t last_avail_idx;
	uint16_t last_used_idx;
	uint16_t id;

	bool avail_wrap_counter;
	bool used_wrap_counter;
};

struct vhost_rdma_dev {
	uint16_t eth_port_id;
	int vid;
	int started;

	struct rte_vhost_memory *mem;

	struct rte_ring* tx_ring;
	struct rte_ring* rx_ring;
	struct vhost_rdma_queue vqs[NUM_OF_RDMA_QUEUES];

	struct rte_intr_handle ctrl_intr_handle;
	int ctrl_intr_registed;
	struct virtio_rdma_config config;
};

int vhost_rdma_construct(const char *path, uint16_t eth_port_id,
					struct rte_ring* tx_ring, struct rte_ring* rx_ring);
void vhost_rdma_destroy(const char* path);

#endif
