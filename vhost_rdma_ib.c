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
#include <infiniband/verbs.h>

#include <rte_ethdev.h>
#include <rte_spinlock.h>

#include "vhost_user.h"
#include "vhost_rdma.h"
#include "vhost_rdma_ib.h"
#include "vhost_rdma_pool.h"
#include "vhost_rdma_loc.h"

#define CHK_IOVEC(tp, iov) \
	do { \
		if(iov->iov_len < sizeof(*tp)) { \
			RDMA_LOG_ERR("%s: " #iov " iovec is too small", __func__); \
			return -1; \
		} \
		tp = iov->iov_base; \
	} while(0); \

#define DEFINE_VIRTIO_RDMA_CMD(cmd, handler) [cmd] = {handler, #cmd}

#define CTRL_NO_CMD __rte_unused struct iovec *__in
#define CTRL_NO_RSP __rte_unused struct iovec *__out

static int
vhost_rdma_query_port(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct cmd_query_port *cmd;
	struct virtio_rdma_port_attr* rsp;

	CHK_IOVEC(cmd, in);
	if (cmd->port != 1) {
		RDMA_LOG_ERR("port is not 1");
		return -EINVAL;
	}

	CHK_IOVEC(rsp, out);

	rte_memcpy(rsp, &dev->port_attr, sizeof(*rsp));

	return 0;
}

static int
vhost_rdma_query_pkey(__rte_unused struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct cmd_query_pkey *cmd;
	struct rsp_query_pkey *rsp;

	CHK_IOVEC(cmd, in);
	if (cmd->index > 0) {
		RDMA_LOG_ERR("pkey index is not 0");
		return -EINVAL;
	}

	CHK_IOVEC(rsp, out);

	rsp->pkey = IB_DEFAULT_PKEY_FULL;

	return 0;
}

static int
vhost_rdma_add_gid(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct cmd_add_gid *cmd;
	struct vhost_rdma_gid *gid;

	CHK_IOVEC(cmd, in);
	if (cmd->index >= VHOST_MAX_GID_TBL_LEN) {
		RDMA_LOG_ERR("gid index is too big");
		return -EINVAL;
	}

	RDMA_LOG_INFO("add gid %d", cmd->index);

	gid = &dev->gid_tbl[cmd->index];

	rte_memcpy(&gid->gid.raw, cmd->gid, 16);
	gid->type = cmd->gid_type;

	print_gid(&dev->gid_tbl[cmd->index]);

	return 0;
}

static int
vhost_rdma_del_gid(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct cmd_del_gid *cmd;

	CHK_IOVEC(cmd, in);
	if (cmd->index >= VHOST_MAX_GID_TBL_LEN) {
		RDMA_LOG_ERR("gid index is too big");
		return -EINVAL;
	}

	RDMA_LOG_INFO("del gid %d", cmd->index);

	dev->gid_tbl[cmd->index].type = VHOST_RDMA_GID_TYPE_ILLIGAL;

	return 0;
}

static int
vhost_rdma_create_pd(struct vhost_rdma_dev *dev, CTRL_NO_CMD, struct iovec *out)
{
	struct rsp_create_pd *rsp;
	struct vhost_rdma_pd *pd;
	uint32_t idx;

	CHK_IOVEC(rsp, out);

	pd = vhost_rdma_pool_alloc(&dev->pd_pool, &idx);
	if(pd == NULL) {
		return -ENOMEM;
	}
	vhost_rdma_ref_init(pd);

	RDMA_LOG_INFO("create pd %u", idx);
	pd->dev = dev;
	pd->pdn = idx;
	rsp->pdn = idx;

	return 0;
}

static int
vhost_rdma_destroy_pd(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct cmd_destroy_pd *cmd;
	struct vhost_rdma_pd *pd;

	CHK_IOVEC(cmd, in);

	pd = vhost_rdma_pool_get(&dev->pd_pool, cmd->pdn);
	vhost_rdma_drop_ref(pd, dev, pd);

	RDMA_LOG_INFO("destroy pd %u", cmd->pdn);

	return 0;
}

static int
vhost_rdma_get_dma_mr(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct cmd_get_dma_mr *cmd;
	struct rsp_get_dma_mr *rsp;
	struct vhost_rdma_pd *pd;
	struct vhost_rdma_mr *mr;
	uint32_t mrn;

	CHK_IOVEC(cmd, in);
	CHK_IOVEC(rsp, out);

	pd = vhost_rdma_pool_get(&dev->pd_pool, cmd->pdn);
	if (unlikely(pd == NULL)) {
		RDMA_LOG_ERR("pd is not found");
		return -EINVAL;
	}

	mr = vhost_rdma_pool_alloc(&dev->mr_pool, &mrn);
	if (mr == NULL) {
		RDMA_LOG_ERR("mr alloc failed");
		return -ENOMEM;
	}

	vhost_rdma_ref_init(mr);
	vhost_rdma_add_ref(pd);

	mr->type = VHOST_MR_TYPE_DMA;
	mr->state = VHOST_MR_STATE_VALID;
	mr->access = cmd->access_flags;
	mr->pd = pd;
	vhost_rdma_mr_init_key(mr, mrn);
	mr->mrn = mrn;

	rsp->lkey = mr->lkey;
	rsp->rkey = mr->rkey;
	rsp->mrn = mrn;

	return 0;
}

static int
vhost_rdma_create_mr(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct cmd_create_mr *cmd;
	struct rsp_create_mr *rsp;
	struct vhost_rdma_pd *pd;
	struct vhost_rdma_mr *mr;
	uint32_t mrn;

	CHK_IOVEC(cmd, in);
	CHK_IOVEC(rsp, out);

	pd = vhost_rdma_pool_get(&dev->pd_pool, cmd->pdn);
	if (unlikely(pd == NULL)) {
		RDMA_LOG_ERR("pd is not found");
		return -EINVAL;
	}

	mr = vhost_rdma_pool_alloc(&dev->mr_pool, &mrn);
	if (mr == NULL) {
		RDMA_LOG_ERR("mr alloc failed");
		return -ENOMEM;
	}

	mr->page_tbl = vhost_rdma_alloc_page_tbl(cmd->max_num_sg);
	if (mr->page_tbl == NULL) {
		return -ENOMEM;
	}

	vhost_rdma_ref_init(mr);
	vhost_rdma_add_ref(pd);

	mr->type = VHOST_MR_TYPE_DMA;
	mr->access = cmd->access_flags;
	mr->pd = pd;
	mr->max_pages = cmd->max_num_sg;
	mr->state = VHOST_MR_STATE_FREE;
	mr->npages = 0;
	vhost_rdma_mr_init_key(mr, mrn);
	// set rkey for fast_reg
	mr->rkey = mr->lkey;
	mr->mrn = mrn;

	rsp->lkey = mr->lkey;
	rsp->rkey = mr->rkey;
	rsp->mrn = mrn;

	return 0;
}

static int
vhost_rdma_map_mr_sg(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct cmd_map_mr_sg *cmd;
	struct rsp_map_mr_sg *rsp;
	struct vhost_rdma_mr *mr;
	uint32_t npages;

	CHK_IOVEC(cmd, in);
	CHK_IOVEC(rsp, out);

	mr = vhost_rdma_pool_get(&dev->mr_pool, cmd->mrn);

	npages = RTE_MIN(mr->max_pages, cmd->npages);
	vhost_rdma_map_pages(dev->mem, mr->page_tbl, cmd->pages, npages);

	mr->va = cmd->start;
	mr->iova = cmd->start;
	mr->length = cmd->length;
	mr->npages = npages;

	rsp->npages = npages;

	return 0;
}

static int
vhost_rdma_reg_user_mr(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct cmd_reg_user_mr *cmd;
	struct rsp_reg_user_mr *rsp;
	struct vhost_rdma_mr *mr;
	struct vhost_rdma_pd *pd;
	uint32_t mrn;

	CHK_IOVEC(cmd, in);
	CHK_IOVEC(rsp, out);

	pd = vhost_rdma_pool_get(&dev->pd_pool, cmd->pdn);
	if (unlikely(pd == NULL)) {
		RDMA_LOG_ERR("pd is not found");
		return -EINVAL;
	}

	mr = vhost_rdma_pool_alloc(&dev->mr_pool, &mrn);
	if (mr == NULL) {
		return -ENOMEM;
	}

	mr->page_tbl = vhost_rdma_alloc_page_tbl(cmd->npages);
	if (mr->page_tbl == NULL) {
		return -ENOMEM;
	}

	vhost_rdma_ref_init(mr);
	vhost_rdma_add_ref(pd);

	vhost_rdma_map_pages(dev->mem, mr->page_tbl, cmd->pages, cmd->npages);
	// FIXME: remove me
	RDMA_LOG_DEBUG("%s", (char*)mr->page_tbl[0][0]);
	strcpy((char*)mr->page_tbl[0][0], "REG SUCCESS");

	mr->pd = pd;
	mr->access = cmd->access_flags;
	mr->length = cmd->length;
	mr->va = cmd->start;
	mr->iova = cmd->virt_addr;
	mr->npages = cmd->npages;
	mr->offset = cmd->start & (TARGET_PAGE_SIZE - 1);
	mr->type = VHOST_MR_TYPE_MR;
	mr->state = VHOST_MR_STATE_VALID;
	mr->max_pages = cmd->npages;
	vhost_rdma_mr_init_key(mr, mrn);
	mr->mrn = mrn;

	rsp->lkey = mr->lkey;
	rsp->rkey = mr->rkey;
	rsp->mrn = mrn;

	return 0;
}

static int
vhost_rdma_dereg_mr(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct cmd_dereg_mr *cmd;
	struct vhost_rdma_mr *mr;

	CHK_IOVEC(cmd, in);

	mr = vhost_rdma_pool_get(&dev->mr_pool, cmd->mrn);
	if (unlikely(mr == NULL)) {
		RDMA_LOG_ERR("mr not found");
	}

	mr->state = VHOST_MR_STATE_ZOMBIE;

	vhost_rdma_drop_ref(mr->pd, dev, pd);
	vhost_rdma_drop_ref(mr, dev, mr);

	RDMA_LOG_DEBUG("destroy mr %u", cmd->mrn);

	return 0;
}

static int
vhost_rdma_create_cq(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct cmd_create_cq *cmd;
	struct rsp_create_cq *rsp;
	struct vhost_rdma_cq *cq;
	uint32_t cqn;

	CHK_IOVEC(cmd, in);
	if (cmd->cqe > dev->config.max_cqe) {
		return -EINVAL;
	}

	CHK_IOVEC(rsp, out);

	cq = vhost_rdma_pool_alloc(&dev->cq_pool, &cqn);
	if (cq == NULL) {
		RDMA_LOG_ERR("cq alloc failed");
	}
	vhost_rdma_ref_init(cq);

	rte_spinlock_init(&cq->cq_lock);
	cq->is_dying = false;
	cq->notify = 0;
	cq->vq = &dev->cq_vqs[cqn];
	cq->cqn = cqn;

	rsp->cqn = cqn;
	RDMA_LOG_INFO("create cq %u", cqn);

	return 0;
}

static int
vhost_rdma_destroy_cq(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct cmd_destroy_cq *cmd;
	struct vhost_rdma_cq *cq;

	CHK_IOVEC(cmd, in);

	cq = vhost_rdma_pool_get(&dev->cq_pool, cmd->cqn);

	rte_spinlock_lock(&cq->cq_lock);
	cq->is_dying = true;
	rte_spinlock_unlock(&cq->cq_lock);

	vhost_rdma_drop_ref(cq, dev, cq);

	RDMA_LOG_DEBUG("destroy cq %u", cmd->cqn);

	return 0;
}

static int
vhost_rdma_req_notify(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct cmd_req_notify *cmd;
	struct vhost_rdma_cq *cq;

	CHK_IOVEC(cmd, in);

	cq = vhost_rdma_pool_get(&dev->cq_pool, cmd->cqn);
	if (unlikely(cq == NULL)) {
		RDMA_LOG_ERR("cq not found");
		return -EINVAL;
	}

	cq->notify = cmd->flags;

	return 0;
}

static int
vhost_rdma_create_qp(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct cmd_create_qp *cmd;
	struct rsp_create_qp *rsp;
	struct vhost_rdma_qp *qp;
	uint32_t qpn;

	CHK_IOVEC(cmd, in);
	CHK_IOVEC(rsp, out);

	switch (cmd->qp_type) {
	case IB_QPT_GSI:
		if (dev->qp_gsi->valid)
			return -EINVAL;
		qp = dev->qp_gsi;
		qpn = 1;
		break;
	case IB_QPT_RC:
	case IB_QPT_UD:
	case IB_QPT_UC:
		qp = vhost_rdma_pool_alloc(&dev->qp_pool, &qpn);
		break;
	default:
		return -EINVAL;
	}

	if (qp == NULL) {
		return -ENOMEM;
	}
	vhost_rdma_ref_init(qp);

	qp->qpn = qpn;
	
	if (vhost_rdma_qp_init(dev, qp, cmd)) {
		RDMA_LOG_ERR("init qp failed");
		vhost_rdma_drop_ref(qp, dev, qp);
		return -EINVAL;
	}

	rsp->qpn = qpn;

	RDMA_LOG_INFO("create qp %u sq %u rq %u", qp->qpn, qp->sq.queue.vq->id,
					qp->rq.queue.vq->id);

	return 0;
}

static int
vhost_rdma_destroy_qp(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct cmd_destroy_qp *cmd;
	struct vhost_rdma_qp* qp;

	CHK_IOVEC(cmd, in);

	qp = vhost_rdma_pool_get(&dev->qp_pool, cmd->qpn);

	vhost_rdma_qp_destroy(qp);

	if (qp->type != IB_QPT_GSI)
		vhost_rdma_drop_ref(qp, dev, qp);

	RDMA_LOG_DEBUG("destroy qp %u", cmd->qpn);

	return 0;
}

static int
vhost_rdma_query_qp(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct cmd_query_qp *cmd;
	struct rsp_query_qp *rsp;
	struct vhost_rdma_qp *qp;

	CHK_IOVEC(cmd, in);
	CHK_IOVEC(rsp, out);

	qp = vhost_rdma_pool_get(&dev->qp_pool, cmd->qpn);

	vhost_rdma_qp_to_attr(qp, &rsp->attr, cmd->attr_mask);

	return 0;
}

static int
vhost_rdma_modify_qp(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct cmd_modify_qp *cmd;
	struct vhost_rdma_qp *qp;
	int err;
	
	CHK_IOVEC(cmd, in);

	qp = vhost_rdma_pool_get(&dev->qp_pool, cmd->qpn);
	if (unlikely(qp == NULL)) {
		RDMA_LOG_ERR("qp not found");
	}

	RDMA_LOG_INFO("modify qp %u", qp->qpn);

	// FIXME: check in driver?
	err = vhost_rdma_qp_chk_attr(dev, qp, &cmd->attr, cmd->attr_mask);
	if (err)
		goto err;

	err = vhost_rdma_qp_from_attr(dev, qp, &cmd->attr, cmd->attr_mask);
	if (err)
		goto err;

	return 0;

err:
	return err;
}

struct {
    int (*handler)(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out);
    const char* name;
} cmd_tbl[] = {
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_QUERY_PORT, vhost_rdma_query_port),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_CREATE_CQ, vhost_rdma_create_cq),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_DESTROY_CQ, vhost_rdma_destroy_cq),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_CREATE_PD, vhost_rdma_create_pd),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_DESTROY_PD, vhost_rdma_destroy_pd),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_GET_DMA_MR, vhost_rdma_get_dma_mr),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_CREATE_MR, vhost_rdma_create_mr),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_MAP_MR_SG, vhost_rdma_map_mr_sg),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_REG_USER_MR, vhost_rdma_reg_user_mr),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_DEREG_MR, vhost_rdma_dereg_mr),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_CREATE_QP, vhost_rdma_create_qp),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_MODIFY_QP, vhost_rdma_modify_qp),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_QUERY_QP, vhost_rdma_query_qp),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_DESTROY_QP, vhost_rdma_destroy_qp),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_QUERY_PKEY, vhost_rdma_query_pkey),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_REQ_NOTIFY_CQ, vhost_rdma_req_notify),
	DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_ADD_GID, vhost_rdma_add_gid),
	DEFINE_VIRTIO_RDMA_CMD(VIRTIO_CMD_DEL_GID, vhost_rdma_del_gid),
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

	/* consume eventfd data */
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
vhost_rdma_init_ib(struct vhost_rdma_dev *dev) {
	struct rte_ether_addr addr;
	uint32_t qpn;

	dev->config.phys_port_cnt = 1;

	dev->config.vendor_id					= 0XFFFFFF;
	dev->config.max_mr_size					= -1ull;
	dev->config.page_size_cap				= 0xfffff000;
	dev->config.max_qp						= 64;
	dev->config.max_qp_wr					= 0x4000;
	dev->config.device_cap_flags			= (1 << 21); // IB_DEVICE_MEM_MGT_EXTENSIONS
	dev->config.max_send_sge				= 32;
	dev->config.max_recv_sge				= 32;
	dev->config.max_sge_rd					= 32;
	dev->config.max_cq						= 64;
	dev->config.max_cqe						= (1 << 15) - 1;
	dev->config.max_mr						= 0x00001000;
	dev->config.max_mw						= 0;
	dev->config.max_pd						= 0x7ffc;
	dev->config.max_qp_rd_atom				= 128;
	dev->config.max_res_rd_atom				= 0x3f000;
	dev->config.max_qp_init_rd_atom			= 128;
	dev->config.atomic_cap					= IB_ATOMIC_HCA;
	dev->config.max_mcast_grp				= 0;
	dev->config.max_mcast_qp_attach			= 0;
	dev->config.max_total_mcast_qp_attach	= 0;
	dev->config.max_ah						= 100;
	dev->config.max_fast_reg_page_list_len	= 512;
	dev->config.max_pkeys					= 1;
	dev->config.local_ca_ack_delay			= 15;

	rte_eth_macaddr_get(dev->eth_port_id, &addr);
	rte_memcpy(&dev->config.sys_image_guid, addr.addr_bytes,
		RTE_MIN(RTE_ETHER_ADDR_LEN, sizeof(dev->config.sys_image_guid)));

	dev->max_inline_data = dev->config.max_send_sge *
							sizeof(struct virtio_rdma_sge);

	dev->port_attr.state			= IB_PORT_ACTIVE;
	dev->port_attr.max_mtu			= IB_MTU_4096;
	dev->port_attr.active_mtu		= IB_MTU_1024;
	dev->port_attr.gid_tbl_len		= VHOST_MAX_GID_TBL_LEN;
	dev->port_attr.port_cap_flags	= 1 << 16; // IB_PORT_CM_SUP
	dev->port_attr.max_msg_sz		= 0x800000;
	dev->port_attr.bad_pkey_cntr	= 0;
	dev->port_attr.qkey_viol_cntr	= 0;
	dev->port_attr.pkey_tbl_len		= VHOST_PORT_PKEY_TBL_LEN;
	dev->port_attr.active_width		= 1; // IB_WIDTH_1X
	dev->port_attr.active_speed		= 1;
	dev->port_attr.phys_state		= 5; // IB_PORT_PHYS_STATE_LINK_UP

	dev->mtu_cap = ib_mtu_enum_to_int(IB_MTU_1024);

	for (int i = 0; i < VHOST_MAX_GID_TBL_LEN; i++) {
		dev->gid_tbl[i].type = VHOST_RDMA_GID_TYPE_ILLIGAL;
	}

	dev->cq_vqs = &dev->vqs[1];
	dev->qp_vqs = &dev->vqs[1 + dev->config.max_cq];

	vhost_rdma_pool_init(&dev->pd_pool, "pd_pool", dev->config.max_pd,
						sizeof(struct vhost_rdma_pd), false, NULL);
	vhost_rdma_pool_init(&dev->mr_pool, "mr_pool", dev->config.max_mr,
						sizeof(struct vhost_rdma_mr), false, vhost_rdma_mr_cleanup);
	vhost_rdma_pool_init(&dev->cq_pool, "cq_pool", dev->config.max_cq,
						sizeof(struct vhost_rdma_cq), true, NULL);
	vhost_rdma_pool_init(&dev->qp_pool, "qp_pool", dev->config.max_qp,
						sizeof(struct vhost_rdma_qp), false, vhost_rdma_qp_cleanup);
	dev->qp_gsi = vhost_rdma_pool_alloc(&dev->qp_pool, &qpn);
	vhost_rdma_add_ref(dev->qp_gsi);
	assert(qpn == 1);
}

void
vhost_rdma_destroy_ib(struct vhost_rdma_dev *dev) {
	vhost_rdma_pool_destroy(&dev->mr_pool);
	vhost_rdma_pool_destroy(&dev->pd_pool);
	vhost_rdma_pool_destroy(&dev->cq_pool);
	vhost_rdma_pool_destroy(&dev->qp_pool);
	vhost_rdma_pool_destroy(&dev->uc_pool);
}
