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

#include <rte_eal.h>

struct virtio_rdma_config {
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
    __le32         max_ee_rd_atom;
    __le32         max_res_rd_atom;
    __le32         max_qp_init_rd_atom;
    __le32         max_ee_init_rd_atom;
    __le32         atomic_cap;
    __le32         max_ee;
    __le32         max_rdd;
    __le32         max_mw;
    __le32         max_mcast_grp;
    __le32         max_mcast_qp_attach;
    __le32         max_total_mcast_qp_attach;
    __le32         max_ah;
    __le32         max_srq;
    __le32         max_srq_wr;
    __le32         max_srq_sge;
    __le32         max_fast_reg_page_list_len;
    __le32         max_pi_fast_reg_page_list_len;
    __le16         max_pkeys;
	uint8_t           local_ca_ack_delay;

    uint8_t           reserved[64];
} __rte_packed;

#endif