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

#include <rte_byteorder.h>

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
		rte_be64_t	subnet_prefix;
		rte_be64_t	interface_id;
	} global;
};

enum ib_ah_flags {
	IB_AH_GRH	= 1
};

bool ib_modify_qp_is_ok(enum ib_qp_state cur_state, enum ib_qp_state next_state,
			enum ib_qp_type type, enum ib_qp_attr_mask mask);

enum ib_access_flags {
	IB_ACCESS_LOCAL_WRITE = IB_UVERBS_ACCESS_LOCAL_WRITE,
	IB_ACCESS_REMOTE_WRITE = IB_UVERBS_ACCESS_REMOTE_WRITE,
	IB_ACCESS_REMOTE_READ = IB_UVERBS_ACCESS_REMOTE_READ,
	IB_ACCESS_REMOTE_ATOMIC = IB_UVERBS_ACCESS_REMOTE_ATOMIC,
	IB_ACCESS_MW_BIND = IB_UVERBS_ACCESS_MW_BIND,
	IB_ZERO_BASED = IB_UVERBS_ACCESS_ZERO_BASED,
	IB_ACCESS_ON_DEMAND = IB_UVERBS_ACCESS_ON_DEMAND,
	IB_ACCESS_HUGETLB = IB_UVERBS_ACCESS_HUGETLB,
	IB_ACCESS_RELAXED_ORDERING = IB_UVERBS_ACCESS_RELAXED_ORDERING,

	IB_ACCESS_OPTIONAL = IB_UVERBS_ACCESS_OPTIONAL_RANGE,
	IB_ACCESS_SUPPORTED =
		((IB_ACCESS_HUGETLB << 1) - 1) | IB_ACCESS_OPTIONAL,
};

enum ib_wc_status {
	IB_WC_SUCCESS,
	IB_WC_LOC_LEN_ERR,
	IB_WC_LOC_QP_OP_ERR,
	IB_WC_LOC_EEC_OP_ERR,
	IB_WC_LOC_PROT_ERR,
	IB_WC_WR_FLUSH_ERR,
	IB_WC_MW_BIND_ERR,
	IB_WC_BAD_RESP_ERR,
	IB_WC_LOC_ACCESS_ERR,
	IB_WC_REM_INV_REQ_ERR,
	IB_WC_REM_ACCESS_ERR,
	IB_WC_REM_OP_ERR,
	IB_WC_RETRY_EXC_ERR,
	IB_WC_RNR_RETRY_EXC_ERR,
	IB_WC_LOC_RDD_VIOL_ERR,
	IB_WC_REM_INV_RD_REQ_ERR,
	IB_WC_REM_ABORT_ERR,
	IB_WC_INV_EECN_ERR,
	IB_WC_INV_EEC_STATE_ERR,
	IB_WC_FATAL_ERR,
	IB_WC_RESP_TIMEOUT_ERR,
	IB_WC_GENERAL_ERR
};

enum ib_wc_opcode {
	IB_WC_SEND = IBV_WC_SEND,
	IB_WC_RDMA_WRITE = IBV_WC_RDMA_WRITE,
	IB_WC_RDMA_READ = IBV_WC_RDMA_READ,
	IB_WC_COMP_SWAP = IBV_WC_COMP_SWAP,
	IB_WC_FETCH_ADD = IBV_WC_FETCH_ADD,
	IB_WC_BIND_MW = IBV_WC_BIND_MW,
	IB_WC_LOCAL_INV = IBV_WC_LOCAL_INV,
	IB_WC_LSO = IBV_WC_TSO,
	IB_WC_REG_MR,
	IB_WC_MASKED_COMP_SWAP,
	IB_WC_MASKED_FETCH_ADD,
/*
 * Set value of IB_WC_RECV so consumers can test if a completion is a
 * receive by testing (opcode & IB_WC_RECV).
 */
	IB_WC_RECV			= 1 << 7,
	IB_WC_RECV_RDMA_WITH_IMM
};

enum ib_wc_flags {
	IB_WC_GRH		= 1,
	IB_WC_WITH_IMM		= (1<<1),
	IB_WC_WITH_INVALIDATE	= (1<<2),
	IB_WC_IP_CSUM_OK	= (1<<3),
	IB_WC_WITH_SMAC		= (1<<4),
	IB_WC_WITH_VLAN		= (1<<5),
	IB_WC_WITH_NETWORK_HDR_TYPE	= (1<<6),
};

enum ib_cq_notify_flags {
	IB_CQ_SOLICITED			= 1 << 0,
	IB_CQ_NEXT_COMP			= 1 << 1,
	IB_CQ_SOLICITED_MASK		= IB_CQ_SOLICITED | IB_CQ_NEXT_COMP,
	IB_CQ_REPORT_MISSED_EVENTS	= 1 << 2,
};

enum ib_rnr_timeout {
	IB_RNR_TIMER_655_36 =  0,
	IB_RNR_TIMER_000_01 =  1,
	IB_RNR_TIMER_000_02 =  2,
	IB_RNR_TIMER_000_03 =  3,
	IB_RNR_TIMER_000_04 =  4,
	IB_RNR_TIMER_000_06 =  5,
	IB_RNR_TIMER_000_08 =  6,
	IB_RNR_TIMER_000_12 =  7,
	IB_RNR_TIMER_000_16 =  8,
	IB_RNR_TIMER_000_24 =  9,
	IB_RNR_TIMER_000_32 = 10,
	IB_RNR_TIMER_000_48 = 11,
	IB_RNR_TIMER_000_64 = 12,
	IB_RNR_TIMER_000_96 = 13,
	IB_RNR_TIMER_001_28 = 14,
	IB_RNR_TIMER_001_92 = 15,
	IB_RNR_TIMER_002_56 = 16,
	IB_RNR_TIMER_003_84 = 17,
	IB_RNR_TIMER_005_12 = 18,
	IB_RNR_TIMER_007_68 = 19,
	IB_RNR_TIMER_010_24 = 20,
	IB_RNR_TIMER_015_36 = 21,
	IB_RNR_TIMER_020_48 = 22,
	IB_RNR_TIMER_030_72 = 23,
	IB_RNR_TIMER_040_96 = 24,
	IB_RNR_TIMER_061_44 = 25,
	IB_RNR_TIMER_081_92 = 26,
	IB_RNR_TIMER_122_88 = 27,
	IB_RNR_TIMER_163_84 = 28,
	IB_RNR_TIMER_245_76 = 29,
	IB_RNR_TIMER_327_68 = 30,
	IB_RNR_TIMER_491_52 = 31
};

#endif
