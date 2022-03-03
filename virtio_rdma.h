/*
 * Vhost-user RDMA device demo: virtio rdma spec
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

#ifndef __VIRTIO_RDMA_SPCE_H__
#define __VIRTIO_RDMA_SPCE_H__

#include <linux/types.h>
#include <linux/if_ether.h>
#include <infiniband/verbs.h>

#include <rte_eal.h>

#include "verbs.h"

struct virtio_rdma_config {
	uint8_t mac[ETH_ALEN];
	/* See VIRTIO_NET_F_STATUS and VIRTIO_NET_S_* above */
	__le16 status;
	/* Maximum number of each of transmit and receive queues;
	 * see VIRTIO_NET_F_MQ and VIRTIO_NET_CTRL_MQ.
	 * Legal values are between 1 and 0x8000
	 */
	__le16 max_virtqueue_pairs;
	/* Default maximum transmit unit advice */
	__le16 mtu;
	/*
	 * speed, in units of 1Mb. All values 0 to INT_MAX are legal.
	 * Any other value stands for unknown.
	 */
	uint32_t speed;
	/*
	 * 0x00 - half duplex
	 * 0x01 - full duplex
	 * Any other value stands for unknown.
	 */
	uint8_t duplex;
	/* maximum size of RSS key */
	uint8_t rss_max_key_size;
	/* maximum number of indirection table entries */
	uint16_t rss_max_indirection_table_length;
	/* bitmask of supported VIRTIO_NET_RSS_HASH_ types */
	uint32_t supported_hash_types;

    __le32         phys_port_cnt;

    __le64         sys_image_guid;
    __le32         vendor_id;
    __le32         vendor_part_id;
    __le32         hw_ver;
    __le64         max_mr_size;
    __le64         page_size_cap;
    __le32         max_qp;
    __le32         max_qp_wr;
    __le64         device_cap_flags;
    __le32         max_send_sge;
    __le32         max_recv_sge;
    __le32         max_sge_rd;
    __le32         max_cq;
    __le32         max_cqe;
    __le32         max_mr;
    __le32         max_pd;
    __le32         max_qp_rd_atom;
    __le32         max_res_rd_atom;
    __le32         max_qp_init_rd_atom;
    __le32         atomic_cap;
    __le32         max_mw;
    __le32         max_mcast_grp;
    __le32         max_mcast_qp_attach;
    __le32         max_total_mcast_qp_attach;
    __le32         max_ah;
    __le32         max_fast_reg_page_list_len;
    __le32         max_pi_fast_reg_page_list_len;
    __le16         max_pkeys;
    uint8_t        local_ca_ack_delay;
} __rte_packed;


#define VIRTIO_RDMA_CTRL_OK    0
#define VIRTIO_RDMA_CTRL_ERR   1

enum {
    VIRTIO_CMD_ILLEGAL,
    VIRTIO_CMD_QUERY_PORT,
    VIRTIO_CMD_CREATE_CQ,
    VIRTIO_CMD_DESTROY_CQ,
    VIRTIO_CMD_CREATE_PD,
    VIRTIO_CMD_DESTROY_PD,
    VIRTIO_CMD_GET_DMA_MR,
    VIRTIO_CMD_CREATE_MR,
	VIRTIO_CMD_MAP_MR_SG,
    VIRTIO_CMD_REG_USER_MR,
	VIRTIO_CMD_DEREG_MR,
    VIRTIO_CMD_CREATE_QP,
    VIRTIO_CMD_MODIFY_QP,
	VIRTIO_CMD_QUERY_QP,
    VIRTIO_CMD_DESTROY_QP,
	VIRTIO_CMD_QUERY_PKEY,
    VIRTIO_CMD_ADD_GID,
    VIRTIO_CMD_DEL_GID,
    VIRTIO_CMD_REQ_NOTIFY_CQ,
	VIRTIO_MAX_CMD_NUM,
};

struct virtio_rdma_port_attr {
	enum ib_port_state	state;
	enum ib_mtu	 max_mtu;
	enum ib_mtu	 active_mtu;
	uint32_t          phys_mtu;
	int               gid_tbl_len;
	uint32_t          port_cap_flags;
	uint32_t          max_msg_sz;
	uint32_t          bad_pkey_cntr;
	uint32_t          qkey_viol_cntr;
	uint16_t          pkey_tbl_len;
	uint8_t           active_width;
	uint16_t          active_speed;
	uint8_t           phys_state;
	uint32_t          reserved[32];
};

enum virtio_rdma_wr_opcode {
	VIRTIO_RDMA_WR_RDMA_WRITE,
	VIRTIO_RDMA_WR_RDMA_WRITE_WITH_IMM,
	VIRTIO_RDMA_WR_SEND,
	VIRTIO_RDMA_WR_SEND_WITH_IMM,
	VIRTIO_RDMA_WR_RDMA_READ,
	VIRTIO_RDMA_WR_ATOMIC_CMP_AND_SWP,
	VIRTIO_RDMA_WR_ATOMIC_FETCH_AND_ADD,
	VIRTIO_RDMA_WR_LOCAL_INV,
	VIRTIO_RDMA_WR_BIND_MW,
	VIRTIO_RDMA_WR_SEND_WITH_INV,
	VIRTIO_RDMA_WR_TSO,
	VIRTIO_RDMA_WR_RDMA_READ_WITH_INV,
	VIRTIO_RDMA_WR_MASKED_ATOMIC_CMP_AND_SWP,
	VIRTIO_RDMA_WR_MASKED_ATOMIC_FETCH_AND_ADD,

	VIRTIO_RDMA_WR_REG_MR = 0x20,
};

struct virtio_rdma_cqe {
	uint64_t		wr_id;
	enum ib_wc_status status;
	enum ib_wc_opcode opcode;
	uint32_t vendor_err;
	uint32_t byte_len;
	union {
		uint32_t imm_data;
		uint32_t invalidate_rkey;
	}ex;
	uint32_t qp_num;
	uint32_t src_qp;
	int	 wc_flags;
	uint16_t pkey_index;
	uint16_t slid;
	uint8_t sl;
	uint8_t dlid_path_bits;
	uint8_t port_num;
};

struct virtio_rdma_global_route {
	union ib_gid	dgid;
	uint32_t		flow_label;
	uint8_t			sgid_index;
	uint8_t			hop_limit;
	uint8_t			traffic_class;
};

struct roce_ah_attr {
	uint8_t			dmac[6];
};

struct virtio_rdma_ah_attr {
	struct virtio_rdma_global_route	grh;
	uint8_t		sl;
	uint8_t		static_rate;
	uint8_t		port_num;
	uint8_t		ah_flags;
	struct roce_ah_attr roce;
};

struct virtio_rdma_qp_cap {
	uint32_t		max_send_wr;
	uint32_t		max_recv_wr;
	uint32_t		max_send_sge;
	uint32_t		max_recv_sge;
	uint32_t		max_inline_data;
};

struct virtio_rdma_qp_attr {
	enum ib_qp_state	qp_state;
	enum ib_qp_state	cur_qp_state;
	enum ib_mtu		path_mtu;
	enum ib_mig_state	path_mig_state;
	uint32_t			qkey;
	uint32_t			rq_psn;
	uint32_t			sq_psn;
	uint32_t			dest_qp_num;
	uint32_t			qp_access_flags;
	uint16_t			pkey_index;
	uint16_t			alt_pkey_index;
	uint8_t			en_sqd_async_notify;
	uint8_t			sq_draining;
	uint8_t			max_rd_atomic;
	uint8_t			max_dest_rd_atomic;
	uint8_t			min_rnr_timer;
	uint8_t			port_num;
	uint8_t			timeout;
	uint8_t			retry_cnt;
	uint8_t			rnr_retry;
	uint8_t			alt_port_num;
	uint8_t			alt_timeout;
	uint32_t			rate_limit;
	struct virtio_rdma_qp_cap	cap;
	struct virtio_rdma_ah_attr	ah_attr;
	struct virtio_rdma_ah_attr	alt_ah_attr;
};

enum {
	VIRTIO_RDMA_NOTIFY_NOT = (0),
	VIRTIO_RDMA_NOTIFY_SOLICITED = (1 << 0),
	VIRTIO_RDMA_NOTIFY_NEXT_COMPLETION = (1 << 1)
};

struct control_buf {
    uint8_t cmd;
    uint8_t status;
};

struct cmd_query_port {
    uint32_t port;
};

struct cmd_add_gid {
	uint8_t gid[16];
	uint32_t gid_type;
	uint16_t index;
	uint32_t port_num;
};

struct cmd_del_gid {
	uint16_t index;
	uint32_t port_num;
};

struct cmd_create_cq {
    uint32_t cqe;
};

struct rsp_create_cq {
    uint32_t cqn;
};

struct cmd_destroy_cq {
    uint32_t cqn;
};

struct rsp_create_pd {
    uint32_t pdn;
};

struct cmd_destroy_pd {
    uint32_t pdn;
};

struct cmd_get_dma_mr {
    uint32_t pdn;
    uint32_t access_flags;
};

struct rsp_get_dma_mr {
    uint32_t mrn;
    uint32_t lkey;
    uint32_t rkey;
};

struct cmd_create_mr {
    uint32_t pdn;
    uint32_t access_flags;

	uint32_t max_num_sg;
};

struct rsp_create_mr {
    uint32_t mrn;
    uint32_t lkey;
    uint32_t rkey;
};

struct cmd_map_mr_sg {
	uint32_t mrn;
	uint32_t npages;
	uint64_t start;
	uint64_t length;

	uint64_t pages;
};

struct rsp_map_mr_sg {
	uint32_t npages;
};

struct cmd_reg_user_mr {
	uint32_t pdn;
	uint32_t access_flags;
	uint64_t start;
	uint64_t length;
    uint64_t virt_addr;

	uint64_t pages;
	uint32_t npages;
};

struct rsp_reg_user_mr {
	uint32_t mrn;
	uint32_t lkey;
	uint32_t rkey;
};

struct cmd_dereg_mr {
    uint32_t mrn;
};

struct rsp_dereg_mr {
    uint32_t mrn;
};

struct cmd_create_qp {
    uint32_t pdn;
    uint8_t qp_type;
	uint8_t sq_sig_type;
    uint32_t max_send_wr;
    uint32_t max_send_sge;
    uint32_t send_cqn;
    uint32_t max_recv_wr;
    uint32_t max_recv_sge;
    uint32_t recv_cqn;

	uint32_t max_inline_data;
};

struct rsp_create_qp {
    uint32_t qpn;
};

struct cmd_modify_qp {
    uint32_t qpn;
    uint32_t attr_mask;
    struct virtio_rdma_qp_attr attr;
};

struct cmd_destroy_qp {
    uint32_t qpn;
};

struct rsp_destroy_qp {
    uint32_t qpn;
};

struct cmd_query_qp {
	uint32_t qpn;
	uint32_t attr_mask;
};

struct rsp_query_qp {
	struct virtio_rdma_qp_attr attr;
};

struct cmd_query_gid {
    uint32_t port;
    uint32_t index;
};

struct cmd_query_pkey {
	uint32_t port;
	uint16_t index;
};

struct rsp_query_pkey {
	uint16_t pkey;
};

struct cmd_req_notify {
	uint32_t cqn;
	uint32_t flags;
};

struct rsp_req_notify {
	uint32_t status;
};

struct virtio_rdma_av {
	uint32_t port;
    uint32_t pdn;
	uint32_t sl_tclass_flowlabel;
	uint8_t dgid[16];
	uint8_t gid_index;
	uint8_t stat_rate;
	uint8_t hop_limit;
	uint8_t dmac[6];
	uint8_t reserved[6];
};

struct cmd_post_send {
	uint32_t num_sge;

	int send_flags;
	enum virtio_rdma_wr_opcode opcode;
	uint64_t wr_id;

	union {
		__be32 imm_data;
		uint32_t invalidate_rkey;
	} ex;
	
	union {
		struct {
			uint64_t remote_addr;
			uint32_t rkey;
		} rdma;
		struct {
			uint64_t remote_addr;
			uint64_t compare_add;
			uint64_t swap;
			uint32_t rkey;
		} atomic;
		struct {
			uint32_t remote_qpn;
			uint32_t remote_qkey;
			struct virtio_rdma_av av;
		} ud;
        struct {
			uint32_t mrn;
			uint32_t key;
			int access;
		} reg;
	} wr;
};

struct cmd_post_recv {
	uint32_t num_sge;
	uint64_t wr_id;
};

struct virtio_rdma_sge {
    __u64 addr;
    __u32 length;
    __u32 lkey;
};

#endif