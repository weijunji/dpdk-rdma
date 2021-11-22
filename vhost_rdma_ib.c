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

#include <unistd.h>
#include <sys/uio.h>

#include <rte_ethdev.h>

#include "vhost_user.h"
#include "vhost_rdma.h"
#include "vhost_rdma_ib.h"

static int
desc_payload_to_iovs(struct rte_vhost_memory *mem, struct iovec *iovs,
		     uint32_t *iov_index, uintptr_t payload, uint64_t remaining, uint16_t num_iovs)
{
	void *vva;
	uint64_t len;

	do {
		if (*iov_index >= num_iovs) {
			RDMA_LOG_ERR("MAX_IOVS reached");
			return -1;
		}
		len = remaining;
		vva = (void *)(uintptr_t)gpa_to_vva(mem, payload, &len);
		if (!vva || !len) {
			RDMA_LOG_ERR("failed to translate desc address.");
			return -1;
		}

		iovs[*iov_index].iov_base = vva;
		iovs[*iov_index].iov_len = len;
		payload += len;
		remaining -= len;
		(*iov_index)++;
	} while (remaining);

	return 0;
}

static int
setup_iovs_from_descs(struct rte_vhost_memory *mem, struct vhost_queue *vq,
				uint16_t req_idx, struct iovec *iovs, uint16_t num_iovs,
				uint16_t *num_in, uint16_t* num_out)
{
	struct vring_desc *desc = &vq->vring.desc[req_idx];
	struct vring_desc *desc_table;
	uint32_t iovs_idx = 0;
	uint64_t len;
	uint16_t in = 0, out = 0;

	if (desc->flags & VRING_DESC_F_INDIRECT) {
		len = desc->len;
		desc_table = (struct vring_desc *)(uintptr_t)gpa_to_vva(mem, 
							desc->addr, &len);
		if (!desc_table || !len) {
			RDMA_LOG_ERR("failed to translate desc address.");
			return -1;
		}
		assert(len == desc->len);

		/* first is loacted at index 0 */
		desc = desc_table;
	} else {
		desc_table = vq->vring.desc;
	}

	do {
		if (iovs_idx >= num_iovs) {
			RDMA_LOG_ERR("MAX_IOVS reached\n");
			return -1;
		}

		if (desc->flags & VRING_DESC_F_WRITE) {
			in++;
		} else {
			out++;
		}

		if (desc_payload_to_iovs(mem, iovs, &iovs_idx,
			desc->addr, desc->len, num_iovs) != 0) {
			RDMA_LOG_ERR("Failed to convert desc payload to iovs");
			return -1;
		}

		desc = vring_get_next_desc(desc_table, desc);
	} while (desc != NULL);

	*num_in = in;
	*num_out = out;

	return iovs_idx;
}

static void
vhost_queue_push(struct vhost_queue *vq, uint16_t idx, uint32_t len)
{
	struct vring_used *used = vq->vring.used;

	used->ring[used->idx & (vq->vring.size - 1)].id = idx;
	used->ring[used->idx & (vq->vring.size - 1)].len = len;
	rte_smp_mb();
	used->idx++;
	rte_smp_mb();
}

static int
vhost_rdma_query_port(__rte_unused struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct cmd_query_port *cmd;
	struct virtio_rdma_port_attr* rsp;

	if (in->iov_len < sizeof(*cmd)) {
		RDMA_LOG_ERR("%s: in_iovec is too small", __func__);
		return -1;
	}
	cmd = in->iov_base;

	if (cmd->port != 1) {
		RDMA_LOG_ERR("port is not 1");
		return -1;
	}

	if (out->iov_len < sizeof(*rsp)) {
		RDMA_LOG_ERR("%s: out_iovec is too small", __func__);
		return -1;
	}
	rsp = out->iov_base;

	rte_memcpy(rsp, &dev->port_attr[cmd->port - 1], sizeof(*rsp));

	return 0;
}

#define DEFINE_VIRTIO_RDMA_CMD(cmd, handler) [cmd] = {handler, #cmd},

struct {
    int (*handler)(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out);
    const char* name;
} cmd_tbl[] = {
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_QUERY_PORT, vhost_rdma_query_port)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_CREATE_CQ, vu_rdma_create_cq)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_DESTROY_CQ, vu_rdma_destroy_cq)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_CREATE_PD, vu_rdma_create_pd)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_DESTROY_PD, vu_rdma_destroy_pd)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_GET_DMA_MR, virtio_rdma_get_dma_mr)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_CREATE_MR, virtio_rdma_create_mr)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_MAP_MR_SG, virtio_rdma_map_mr_sg)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_REG_USER_MR, vu_rdma_reg_user_mr)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_DEREG_MR, vu_rdma_dereg_mr)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_CREATE_QP, vu_rdma_create_qp)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_MODIFY_QP, vu_rdma_modify_qp)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_QUERY_QP, vu_rdma_query_qp)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_DESTROY_QP, vu_rdma_destroy_qp)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_QUERY_GID, vu_rdma_query_gid)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_CREATE_UC, vu_rdma_create_uc)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_DEALLOC_UC, vu_rdma_dealloc_uc)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_QUERY_PKEY, vu_rdma_query_pkey)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_REQ_NOTIFY_CQ, vu_rdma_req_notify)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_IW_ACCEPT, vu_rdma_accept)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_IW_CONNECT, vu_rdma_connect)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_IW_CREATE_LISTEN,
    //                        vu_rdma_create_listen)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_IW_DESTROY_LISTEN,
    //                        vu_rdma_destroy_listen)
    // DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_IW_REJECT, vu_rdma_reject)
};

void
vhost_rdma_handle_ctrl(void* arg) {
	struct vhost_rdma_dev* dev = arg;
	struct vhost_queue *ctrl_vq = &dev->vqs[0];
	int kick_fd, nbytes;
	eventfd_t kick_data;
	struct iovec iovs[4];
	uint16_t desc_idx, num_in, num_out;
	uint8_t *cmd, *status;
	struct iovec *in_iovs, *out_iovs;

	RDMA_LOG_DEBUG("rdma ctrl kick");
	/* consuem eventfd data */
	kick_fd = ctrl_vq->vring.kickfd;
	do {
		nbytes = eventfd_read(kick_fd, &kick_data);
		if (nbytes < 0) {
			if (errno == EINTR ||
				errno == EWOULDBLOCK ||
				errno == EAGAIN)
				continue;
			RDMA_LOG_ERR("Failed to read kickfd of ctrl virtq: %s",
				strerror(errno));
		}
		break;
	} while (1);

	rte_vhost_enable_guest_notification(dev->vid, 0, 0);

	while(vhost_vq_is_avail(ctrl_vq)) {
		desc_idx = vq_get_desc_idx(ctrl_vq);

		if (setup_iovs_from_descs(dev->mem, ctrl_vq, desc_idx, iovs, 4,
			&num_in, &num_out) < 0) {
			RDMA_LOG_ERR("read from desc failed");
			goto out;
		}

		out_iovs = iovs;
		in_iovs = &iovs[num_out];

		cmd = out_iovs[0].iov_base;
		status = in_iovs[0].iov_base;

		RDMA_LOG_DEBUG("%u %u %u %u", num_in, num_out, *cmd, *status);

		if (out_iovs[0].iov_len != sizeof(*cmd)) {
			*status = VIRTIO_RDMA_CTRL_ERR;
		} else {
			if (*cmd == VIRTIO_CMD_ILLEGAL || *cmd >= VIRTIO_MAX_CMD_NUM) {
 				RDMA_LOG_ERR("unknown cmd %d", *cmd);
				*status = VIRTIO_RDMA_CTRL_ERR;
			} else {
				if (cmd_tbl[*cmd].handler) {
					RDMA_LOG_INFO("cmd=%d %s", *cmd, cmd_tbl[*cmd].name);
					*status = cmd_tbl[*cmd].handler(dev,
						num_out > 1 ? &out_iovs[1] : NULL,
						num_in > 1 ? &in_iovs[1] : NULL);
				} else {
					RDMA_LOG_ERR("no handler for cmd %d\n", *cmd);
					*status = VIRTIO_RDMA_CTRL_ERR;
				}
			}
		}

		vhost_queue_push(ctrl_vq, desc_idx, sizeof(*status));
		vhost_queue_notify(dev->vid, ctrl_vq);
	}
out:
	rte_vhost_enable_guest_notification(dev->vid, 0, 1);
}

void
vhost_rdma_init_config(struct vhost_rdma_dev *dev) {
	struct rte_ether_addr addr;

	dev->config.phys_port_cnt = 1;
	dev->config.max_cq = 64;
	dev->config.max_qp = 64;
	dev->config.max_srq = 0;

	dev->config.vendor_id			= 0XFFFFFF;
	dev->config.max_mr_size			= -1ull;
	dev->config.page_size_cap			= 0xfffff000;
	dev->config.max_qp			= 64;
	dev->config.max_qp_wr			= 0x4000;
	dev->config.device_cap_flags		= 0;
	dev->config.max_send_sge			= 32;
	dev->config.max_recv_sge			= 32;
	dev->config.max_sge_rd			= 32;
	dev->config.max_cq			= 64;
	dev->config.max_cqe			= (1 << 15) - 1;
	dev->config.max_mr			= 0x00001000;
	dev->config.max_mw			= 0;
	dev->config.max_pd			= 0x7ffc;
	dev->config.max_qp_rd_atom		= 128;
	dev->config.max_res_rd_atom		= 0x3f000;
	dev->config.max_qp_init_rd_atom		= 128;
	dev->config.atomic_cap			= IBV_ATOMIC_HCA;
	dev->config.max_mcast_grp			= 0;
	dev->config.max_mcast_qp_attach		= 0;
	dev->config.max_total_mcast_qp_attach	= 0;
	dev->config.max_ah			= 100;
	dev->config.max_srq			= 0;
	dev->config.max_srq_wr			= 0;
	dev->config.max_srq_sge			= 0;
	dev->config.max_fast_reg_page_list_len	= 512;
	dev->config.max_pkeys			= 1;
	dev->config.local_ca_ack_delay		= 15;

	rte_eth_macaddr_get(dev->eth_port_id, &addr);
	rte_memcpy(&dev->config.sys_image_guid, addr.addr_bytes, 
		RTE_MIN(RTE_ETHER_ADDR_LEN, sizeof(dev->config.sys_image_guid)));

	for (int i = 0; i < NUM_OF_RDMA_PORT; i++) {
		dev->port_attr[i].state				= IBV_PORT_ACTIVE;
		dev->port_attr[i].max_mtu			= IBV_MTU_4096;
		dev->port_attr[i].active_mtu		= IBV_MTU_256;
		dev->port_attr[i].gid_tbl_len		= VHOST_MAX_GID_TBL_LEN;
		dev->port_attr[i].port_cap_flags	= IBV_PORT_CM_SUP;
		dev->port_attr[i].max_msg_sz		= 0x800000;
		dev->port_attr[i].bad_pkey_cntr		= 0;
		dev->port_attr[i].qkey_viol_cntr	= 0;
		dev->port_attr[i].pkey_tbl_len		= VHOST_PORT_PKEY_TBL_LEN;
		dev->port_attr[i].lid				= 0;
		dev->port_attr[i].sm_lid			= 0;
		dev->port_attr[i].lmc				= 0;
		dev->port_attr[i].max_vl_num		= VHOST_PORT_MAX_VL_NUM;
		dev->port_attr[i].sm_sl				= 0;
		dev->port_attr[i].subnet_timeout	= 0;
		dev->port_attr[i].init_type_reply	= 0;
		dev->port_attr[i].active_width		= 1; // IB_WIDTH_1X
		dev->port_attr[i].active_speed		= 1;
		dev->port_attr[i].phys_state		= 5; // IB_PORT_PHYS_STATE_LINK_UP
		dev->port_attr[i].port_cap_flags2 	= 0;
	}
}
