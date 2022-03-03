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

#include "verbs.h"
#include "virtio_rdma.h"
#include "vhost_user.h"
#include "vhost_rdma_pool.h"

#define MAX_PKTS_BURST 32

#define TARGET_PAGE_SIZE 4096
#define PAGE_MASK	(~(TARGET_PAGE_SIZE-1))

#define RTE_LOGTYPE_RDMA RTE_LOGTYPE_USER2

#define RDMA_LOG_DEBUG(f, ...) RTE_LOG(DEBUG, RDMA, f "\n", ##__VA_ARGS__)
#define RDMA_LOG_INFO(f, ...) RTE_LOG(INFO, RDMA, f "\n", ##__VA_ARGS__)
#define RDMA_LOG_ERR(f, ...) RTE_LOG(ERR, RDMA, f "\n", ##__VA_ARGS__)

#ifdef DEBUG_RDMA_DP
#define RDMA_LOG_DEBUG_DP(f, ...) RTE_LOG(DEBUG, RDMA, "[%u] " f "\n", \
										rte_lcore_id(), ##__VA_ARGS__)
#define RDMA_LOG_INFO_DP(f, ...) RTE_LOG(INFO, RDMA, "[%u] " f "\n", \
										rte_lcore_id(), ##__VA_ARGS__)
#define RDMA_LOG_ERR_DP(f, ...) RTE_LOG(ERR, RDMA, "[%u] " f "\n", \
										rte_lcore_id(), ##__VA_ARGS__)
#else
#define RDMA_LOG_DEBUG_DP(f, ...) RTE_LOG_DP(DEBUG, RDMA, "[%u] " f "\n", \
										rte_lcore_id(), ##__VA_ARGS__)
#define RDMA_LOG_INFO_DP(f, ...) RTE_LOG_DP(INFO, RDMA, "[%u] " f "\n", \
										rte_lcore_id(), ##__VA_ARGS__)
#define RDMA_LOG_ERR_DP(f, ...) RTE_LOG_DP(ERR, RDMA, "[%u] " f "\n", \
										rte_lcore_id(), ##__VA_ARGS__)
#endif

#define ROCE_V2_UDP_DPORT 4791

#define NUM_OF_RDMA_QUEUES 195 // 2 + 1 + 64 * 2 + 64

#define VHOST_NET_RXQ 0
#define VHOST_NET_TXQ 1
#define VHOST_NET_ROCE_CTRL_QUEUE 2

#define NUM_OF_RDMA_PORT 1

#define VHOST_MAX_GID_TBL_LEN 512
#define VHOST_PORT_PKEY_TBL_LEN 1

#define VHOST_MAX_PD_NUM 0x7ffc

#define VHOST_MAX_UNACKED_PSNS 128
#define VHOST_INFLIGHT_SKBS_PER_QP_HIGH 64
#define VHOST_INFLIGHT_SKBS_PER_QP_LOW 16
#define VHOST_MAX_PKT_PER_ACK 64

#define IB_DEFAULT_PKEY_FULL	0xFFFF

#define VIRTIO_NET_F_ROCE	55

/* VIRTIO_F_EVENT_IDX is NOT supported now */
#define VHOST_RDMA_FEATURE ((1ULL << VIRTIO_F_VERSION_1) |\
	(1ULL << VIRTIO_RING_F_INDIRECT_DESC) | \
	(1ULL << VHOST_USER_F_PROTOCOL_FEATURES) | \
	(1ULL << VHOST_USER_PROTOCOL_F_STATUS) | \
	(1ULL << VIRTIO_NET_F_ROCE))

struct vhost_rdma_gid {
	#define VHOST_RDMA_GID_TYPE_ILLIGAL (-1u)
	uint32_t type;
	union ib_gid gid;
};

enum vhost_rdma_counters {
	VHOST_CNT_SENT_PKTS,
	VHOST_CNT_RCVD_PKTS,
	VHOST_CNT_DUP_REQ,
	VHOST_CNT_OUT_OF_SEQ_REQ,
	VHOST_CNT_RCV_RNR,
	VHOST_CNT_SND_RNR,
	VHOST_CNT_RCV_SEQ_ERR,
	VHOST_CNT_COMPLETER_SCHED,
	VHOST_CNT_RETRY_EXCEEDED,
	VHOST_CNT_RNR_RETRY_EXCEEDED,
	VHOST_CNT_COMP_RETRY,
	VHOST_CNT_SEND_ERR,
	VHOST_CNT_LINK_DOWNED,
	VHOST_CNT_RDMA_SEND,
	VHOST_CNT_RDMA_RECV,
	VHOST_NUM_OF_COUNTERS
};

struct vhost_rdma_dev {
	uint16_t eth_port_id;
	int vid;
	int started;
	bool stoped;

	struct rte_vhost_memory *mem;

	struct rte_mempool *mbuf_pool;
	struct rte_ring* tx_ring;
	struct rte_ring* rx_ring;
	struct vhost_queue vqs[NUM_OF_RDMA_QUEUES];
	struct vhost_queue *rdma_vqs;
	struct vhost_queue *cq_vqs;
	struct vhost_queue *qp_vqs;

	struct rte_ring* task_ring;

	struct rte_intr_handle ctrl_intr_handle;
	int ctrl_intr_registed;

	struct virtio_rdma_config config;
	uint32_t max_inline_data;

	// only one port
	struct virtio_rdma_port_attr port_attr;
	rte_spinlock_t port_lock;
	unsigned int mtu_cap;
	struct vhost_rdma_gid gid_tbl[VHOST_MAX_GID_TBL_LEN];
	struct vhost_rdma_qp *qp_gsi;

	struct vhost_rdma_pool pd_pool;
	struct vhost_rdma_pool mr_pool;
	struct vhost_rdma_pool cq_pool;
	struct vhost_rdma_pool qp_pool;
	struct vhost_rdma_pool uc_pool;

	rte_atomic64_t stats_counters[VHOST_NUM_OF_COUNTERS];
};

static __rte_always_inline void
vhost_rdma_counter_inc(struct vhost_rdma_dev *dev,
						enum vhost_rdma_counters index)
{
	rte_atomic64_inc(&dev->stats_counters[index]);
}

int vhost_rdma_construct(const char *path, uint16_t eth_port_id,
				struct rte_mempool *mbuf_pool, struct rte_ring* tx_ring,
				struct rte_ring* rx_ring);
void vhost_rdma_destroy(const char* path);

static __rte_always_inline void
print_gid(struct vhost_rdma_gid *gid) {
	uint8_t *raw = gid->gid.raw;
	RDMA_LOG_DEBUG(
	"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	raw[0], raw[1], raw[2], raw[4], raw[5], raw[6], raw[7], raw[8],
	raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15], raw[16]);
}

#endif
