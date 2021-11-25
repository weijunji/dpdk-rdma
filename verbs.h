/*
 * Vhost-user RDMA device demo: ib verbs, copy from kernel
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

#ifndef __VHOST_RDMA_VERBS_H__
#define __VHOST_RDMA_VERBS_H__

#include <infiniband/verbs.h>

enum ib_sig_type {
	IB_SIGNAL_ALL_WR,
	IB_SIGNAL_REQ_WR
};

enum ib_qp_type {
	IB_QPT_SMI,
	IB_QPT_GSI,

	IB_QPT_RC = IBV_QPT_RC,
	IB_QPT_UC = IBV_QPT_UC,
	IB_QPT_UD = IBV_QPT_UD,
	IB_QPT_MAX,
};

enum ib_qp_state {
	IB_QPS_RESET,
	IB_QPS_INIT,
	IB_QPS_RTR,
	IB_QPS_RTS,
	IB_QPS_SQD,
	IB_QPS_SQE,
	IB_QPS_ERR
};

enum ib_qp_attr_mask {
	IB_QP_STATE			= 1,
	IB_QP_CUR_STATE			= (1<<1),
	IB_QP_EN_SQD_ASYNC_NOTIFY	= (1<<2),
	IB_QP_ACCESS_FLAGS		= (1<<3),
	IB_QP_PKEY_INDEX		= (1<<4),
	IB_QP_PORT			= (1<<5),
	IB_QP_QKEY			= (1<<6),
	IB_QP_AV			= (1<<7),
	IB_QP_PATH_MTU			= (1<<8),
	IB_QP_TIMEOUT			= (1<<9),
	IB_QP_RETRY_CNT			= (1<<10),
	IB_QP_RNR_RETRY			= (1<<11),
	IB_QP_RQ_PSN			= (1<<12),
	IB_QP_MAX_QP_RD_ATOMIC		= (1<<13),
	IB_QP_ALT_PATH			= (1<<14),
	IB_QP_MIN_RNR_TIMER		= (1<<15),
	IB_QP_SQ_PSN			= (1<<16),
	IB_QP_MAX_DEST_RD_ATOMIC	= (1<<17),
	IB_QP_PATH_MIG_STATE		= (1<<18),
	IB_QP_CAP			= (1<<19),
	IB_QP_DEST_QPN			= (1<<20),
	IB_QP_RESERVED1			= (1<<21),
	IB_QP_RESERVED2			= (1<<22),
	IB_QP_RESERVED3			= (1<<23),
	IB_QP_RESERVED4			= (1<<24),
	IB_QP_RATE_LIMIT		= (1<<25),
};

enum ib_mig_state {
	IB_MIG_MIGRATED,
	IB_MIG_REARM,
	IB_MIG_ARMED
};

enum ib_mtu {
	IB_MTU_256  = 1,
	IB_MTU_512  = 2,
	IB_MTU_1024 = 3,
	IB_MTU_2048 = 4,
	IB_MTU_4096 = 5
};

enum rdma_network_type {
	RDMA_NETWORK_IB,
	RDMA_NETWORK_ROCE_V1,
	RDMA_NETWORK_IPV4,
	RDMA_NETWORK_IPV6
};

enum ib_gid_type {
	IB_GID_TYPE_IB = IB_UVERBS_GID_TYPE_IB,
	IB_GID_TYPE_ROCE = IB_UVERBS_GID_TYPE_ROCE_V1,
	IB_GID_TYPE_ROCE_UDP_ENCAP = IB_UVERBS_GID_TYPE_ROCE_V2,
	IB_GID_TYPE_SIZE
};

union ib_gid {
	uint8_t	raw[16];
	struct {
		__be64	subnet_prefix;
		__be64	interface_id;
	} global;
};

enum ib_ah_flags {
	IB_AH_GRH	= 1
};

bool ib_modify_qp_is_ok(enum ib_qp_state cur_state, enum ib_qp_state next_state,
			enum ib_qp_type type, enum ib_qp_attr_mask mask);

#endif
