/*
 * Vhost-user RDMA device demo: queue pair
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

#include <stdbool.h>

#include <rte_malloc.h>

#include "verbs.h"
#include "vhost_rdma.h"
#include "vhost_rdma_ib.h"
#include "vhost_rdma_loc.h"
#include "vhost_rdma_hdr.h"

static int vhost_rdma_qp_init_req(__rte_unused struct vhost_rdma_dev *dev,
							struct vhost_rdma_qp *qp, struct cmd_create_qp *cmd)
{
	int wqe_size;

	qp->src_port = 0xc000;
	qp->sq.max_wr		= cmd->max_send_wr;

	/* These caps are limited by rxe_qp_chk_cap() done by the caller */
	wqe_size = RTE_MAX(cmd->max_send_sge * sizeof(struct virtio_rdma_sge),
			 cmd->max_inline_data);
	qp->sq.max_sge = wqe_size / sizeof(struct virtio_rdma_sge);
	qp->sq.max_inline = wqe_size;
	vhost_rdma_queue_init(qp, &qp->sq.queue, "sq_queue",
			&dev->qp_vqs[qp->qpn * 2], sizeof(struct vhost_rdma_send_wqe) + wqe_size, VHOST_RDMA_QUEUE_SQ);

	qp->req.state		= QP_STATE_RESET;
	qp->req.opcode		= -1;
	qp->comp.opcode		= -1;

	qp->req_pkts = rte_zmalloc(NULL, rte_ring_get_memsize(512), RTE_CACHE_LINE_SIZE);
	if (qp->req_pkts == NULL) {
		RDMA_LOG_ERR("req_pkts malloc failed");
		return -ENOMEM;
	}
	if (rte_ring_init(qp->req_pkts, "req_pkts", 512, RING_F_MP_HTS_ENQ | RING_F_MC_HTS_DEQ) != 0) {
		RDMA_LOG_ERR("req_pkts init failed");
		rte_free(qp->req_pkts);
		return -ENOMEM;
	}
	// qp->req_pkts = rte_ring_create("req_pkts", 512, rte_socket_id(), RING_F_MP_HTS_ENQ | RING_F_MC_HTS_DEQ);
	RDMA_LOG_DEBUG("req pkts qp%p %p", qp, qp->req_pkts);
	qp->req_pkts_head = NULL;

	vhost_rdma_init_task(&qp->req.task, dev->task_ring, qp,
			vhost_rdma_requester, "req");
	vhost_rdma_init_task(&qp->comp.task, dev->task_ring, qp,
			vhost_rdma_completer, "comp");

	qp->qp_timeout_ticks = 0; /* Can't be set for UD/UC in modify_qp */
	if (cmd->qp_type == IB_QPT_RC) {
		rte_timer_init(&qp->rnr_nak_timer); // req_task
		rte_timer_init(&qp->retrans_timer); // comp_task
	}
	return 0;
}

static int vhost_rdma_qp_init_resp(struct vhost_rdma_dev *dev,
						struct vhost_rdma_qp *qp, struct cmd_create_qp *cmd)
{
	if (!qp->srq) {
		qp->rq.max_wr		= cmd->max_recv_wr;
		qp->rq.max_sge		= cmd->max_recv_sge;

		vhost_rdma_queue_init(qp, &qp->rq.queue, "rq_queue",
			&dev->qp_vqs[qp->qpn * 2 + 1], sizeof(struct vhost_rdma_recv_wqe), VHOST_RDMA_QUEUE_RQ);
	}

	qp->resp_pkts = rte_zmalloc(NULL, rte_ring_get_memsize(512), RTE_CACHE_LINE_SIZE);
	if (qp->resp_pkts == NULL) {
		RDMA_LOG_ERR("resp_pkts malloc failed");
		return -ENOMEM;
	}
	if (rte_ring_init(qp->resp_pkts, "resp_pkts", 512, RING_F_MP_HTS_ENQ | RING_F_MC_HTS_DEQ) != 0) {
		RDMA_LOG_ERR("resp_pkts init failed");
		rte_free(qp->resp_pkts);
		return -ENOMEM;
	}
	qp->resp_pkts_head = NULL;

	vhost_rdma_init_task(&qp->resp.task, dev->task_ring, qp,
			vhost_rdma_responder, "resp");

	qp->resp.opcode		= OPCODE_NONE;
	qp->resp.msn		= 0;
	qp->resp.state		= QP_STATE_RESET;

	return 0;
}

static void vhost_rdma_qp_init_misc(__rte_unused struct vhost_rdma_dev *dev,
						struct vhost_rdma_qp *qp, struct cmd_create_qp *cmd)
{
	qp->sq_sig_type		= cmd->sq_sig_type;
	qp->attr.path_mtu	= 1;
	qp->mtu			= ib_mtu_enum_to_int(qp->attr.path_mtu);

	rte_spinlock_init(&qp->state_lock);

	rte_atomic32_set(&qp->ssn, 0);
	rte_atomic32_set(&qp->mbuf_out, 0);
}

int vhost_rdma_qp_init(struct vhost_rdma_dev *dev, struct vhost_rdma_qp *qp,
							struct cmd_create_qp *cmd)
{
	int err;

	qp->pd = vhost_rdma_pool_get(&dev->pd_pool, cmd->pdn);
	qp->scq = vhost_rdma_pool_get(&dev->cq_pool, cmd->send_cqn);
	qp->rcq = vhost_rdma_pool_get(&dev->cq_pool, cmd->recv_cqn);

	vhost_rdma_qp_init_misc(dev, qp, cmd);

	err = vhost_rdma_qp_init_req(dev, qp, cmd);
	if (err)
		goto err;

	err = vhost_rdma_qp_init_resp(dev, qp, cmd);
	if (err)
		goto err;

	qp->attr.qp_state = IB_QPS_RESET;
	qp->valid = 1;
	qp->type = cmd->qp_type;
	qp->dev = dev;

	return 0;

err:
	qp->pd = NULL;
	qp->rcq = NULL;
	qp->scq = NULL;

	return err;
}

void vhost_rdma_qp_destroy(struct vhost_rdma_qp *qp)
{
	qp->valid = 0;
	qp->qp_timeout_ticks = 0;
	vhost_rdma_cleanup_task(&qp->resp.task);

	if (qp->type == IB_QPT_RC) {
		rte_timer_stop_sync(&qp->retrans_timer);
		rte_timer_stop_sync(&qp->rnr_nak_timer);
	}

	vhost_rdma_cleanup_task(&qp->req.task);
	vhost_rdma_cleanup_task(&qp->comp.task);

	/* flush out any receive wr's or pending requests */
	__vhost_rdma_do_task(&qp->req.task);
	if (qp->sq.queue.vq) {
		__vhost_rdma_do_task(&qp->comp.task);
		__vhost_rdma_do_task(&qp->req.task);
	}

	rte_free(qp->req_pkts);
	rte_free(qp->resp_pkts);
}

int vhost_rdma_qp_to_attr(struct vhost_rdma_qp *qp,
						struct virtio_rdma_qp_attr *attr, __rte_unused int mask)
{
	*attr = qp->attr;

	attr->rq_psn				= qp->resp.psn;
	attr->sq_psn				= qp->req.psn;

	attr->cap.max_send_wr			= qp->sq.max_wr;
	attr->cap.max_send_sge			= qp->sq.max_sge;
	attr->cap.max_inline_data		= qp->sq.max_inline;

	if (!qp->srq) {
		attr->cap.max_recv_wr		= qp->rq.max_wr;
		attr->cap.max_recv_sge		= qp->rq.max_sge;
	}

	vhost_rdma_av_to_attr(&qp->pri_av, &attr->ah_attr);
	vhost_rdma_av_to_attr(&qp->alt_av, &attr->alt_ah_attr);

	if (qp->req.state == QP_STATE_DRAIN) {
		attr->sq_draining = 1;
	} else {
		attr->sq_draining = 0;
	}

	RDMA_LOG_DEBUG("attr->sq_draining = %d", attr->sq_draining);

	return 0;
}

static int vhost_rdma_qp_chk_cap(struct vhost_rdma_dev *dev,
								struct virtio_rdma_qp_cap *cap, int has_srq)
{
	if (cap->max_send_wr > dev->config.max_qp_wr) {
		RDMA_LOG_ERR("invalid send wr = %d > %d",
			cap->max_send_wr, dev->config.max_qp_wr);
		goto err1;
	}

	if (cap->max_send_sge > dev->config.max_send_sge) {
		RDMA_LOG_ERR("invalid send sge = %d > %d",
			cap->max_send_sge, dev->config.max_send_sge);
		goto err1;
	}

	if (!has_srq) {
		if (cap->max_recv_wr > dev->config.max_qp_wr) {
			RDMA_LOG_ERR("invalid recv wr = %d > %d",
				cap->max_recv_wr, dev->config.max_qp_wr);
			goto err1;
		}

		if (cap->max_recv_sge > dev->config.max_recv_sge) {
			RDMA_LOG_ERR("invalid recv sge = %d > %d",
				cap->max_recv_sge, dev->config.max_recv_sge);
			goto err1;
		}
	}

	if (cap->max_inline_data > dev->max_inline_data) {
		RDMA_LOG_ERR("invalid max inline data = %d > %d",
			cap->max_inline_data, dev->max_inline_data);
		goto err1;
	}

	return 0;

err1:
	return -EINVAL;
}

int vhost_rdma_qp_chk_attr(struct vhost_rdma_dev *dev, struct vhost_rdma_qp *qp,
			struct virtio_rdma_qp_attr *attr, int mask)
{
	enum ib_qp_state cur_state = (mask & IB_QP_CUR_STATE) ?
					attr->cur_qp_state : qp->attr.qp_state;
	enum ib_qp_state new_state = (mask & IB_QP_STATE) ?
					attr->qp_state : cur_state;

	if (!ib_modify_qp_is_ok(cur_state, new_state, qp->type, mask)) {
		RDMA_LOG_ERR("invalid mask or state for qp");
		goto err1;
	}

	if (mask & IB_QP_STATE) {
		if (cur_state == IB_QPS_SQD) {
			if (qp->req.state == QP_STATE_DRAIN &&
			    new_state != IB_QPS_ERR)
				goto err1;
		}
	}

	if (mask & IB_QP_PORT) {
		if (attr->port_num != 1) {
			RDMA_LOG_ERR("invalid port %u", attr->port_num);
			goto err1;
		}
	}

	if (mask & IB_QP_CAP && vhost_rdma_qp_chk_cap(dev, &attr->cap, !!qp->srq))
		goto err1;

	if (mask & IB_QP_AV && vhost_rdma_av_chk_attr(dev, &attr->ah_attr))
		goto err1;

	if (mask & IB_QP_ALT_PATH) {
		if (vhost_rdma_av_chk_attr(dev, &attr->alt_ah_attr))
			goto err1;
		if (attr->alt_port_num != 1)  {
			RDMA_LOG_ERR("invalid alt port %u", attr->alt_port_num);
			goto err1;
		}
		if (attr->alt_timeout > 31) {
			RDMA_LOG_ERR("invalid QP alt timeout %d > 31",
				attr->alt_timeout);
			goto err1;
		}
	}

	if (mask & IB_QP_PATH_MTU) {
		enum ib_mtu max_mtu = dev->port_attr.max_mtu;
		enum ib_mtu mtu = attr->path_mtu;

		if (mtu > max_mtu) {
			RDMA_LOG_ERR("invalid mtu");
			goto err1;
		}
	}

	if (mask & IB_QP_MAX_QP_RD_ATOMIC) {
		if (attr->max_rd_atomic > dev->config.max_qp_rd_atom) {
			RDMA_LOG_ERR("invalid max_rd_atomic %d > %d",
				attr->max_rd_atomic,
				dev->config.max_qp_rd_atom);
			goto err1;
		}
	}

	if (mask & IB_QP_TIMEOUT) {
		if (attr->timeout > 31) {
			RDMA_LOG_ERR("invalid QP timeout %d > 31",
				attr->timeout);
			goto err1;
		}
	}

	return 0;

err1:
	return -EINVAL;
}

static int
alloc_rd_atomic_resources(struct vhost_rdma_qp *qp, unsigned int n)
{
	qp->resp.res_head = 0;
	qp->resp.res_tail = 0;
	qp->resp.resources = rte_zmalloc(NULL, sizeof(struct resp_res) * n, 0);

	if (!qp->resp.resources)
		return -ENOMEM;

	return 0;
}

void
free_rd_atomic_resource(__rte_unused struct vhost_rdma_qp *qp, struct resp_res *res)
{
	if (res->type == VHOST_ATOMIC_MASK) {
		rte_pktmbuf_free(res->atomic.mbuf);
	} else if (res->type == VHOST_READ_MASK) {
		//if (res->read.mr)
		//	rxe_drop_ref(res->read.mr);
	}
	res->type = 0;
}

static void
free_rd_atomic_resources(struct vhost_rdma_qp *qp)
{
	if (qp->resp.resources) {
		for (int i = 0; i < qp->attr.max_dest_rd_atomic; i++) {
			struct resp_res *res = &qp->resp.resources[i];

			free_rd_atomic_resource(qp, res);
		}
		rte_free(qp->resp.resources);
		qp->resp.resources = NULL;
	}
}

int
vhost_rdma_qp_from_attr(struct vhost_rdma_dev *dev, struct vhost_rdma_qp *qp,
						struct virtio_rdma_qp_attr *attr, int mask)
{
	int err;

	if (mask & IB_QP_MAX_QP_RD_ATOMIC) {
		int max_rd_atomic = attr->max_rd_atomic ?
			roundup_pow_of_two(attr->max_rd_atomic) : 0;

		qp->attr.max_rd_atomic = max_rd_atomic;
		rte_atomic32_set(&qp->req.rd_atomic, max_rd_atomic);
	}

	if (mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		int max_dest_rd_atomic = attr->max_dest_rd_atomic ?
			roundup_pow_of_two(attr->max_dest_rd_atomic) : 0;

		qp->attr.max_dest_rd_atomic = max_dest_rd_atomic;

		free_rd_atomic_resources(qp);

		err = alloc_rd_atomic_resources(qp, max_dest_rd_atomic);
		if (err)
			return err;
	}

	if (mask & IB_QP_CUR_STATE)
		qp->attr.cur_qp_state = attr->qp_state;

	if (mask & IB_QP_EN_SQD_ASYNC_NOTIFY)
		qp->attr.en_sqd_async_notify = attr->en_sqd_async_notify;

	if (mask & IB_QP_ACCESS_FLAGS)
		qp->attr.qp_access_flags = attr->qp_access_flags;

	if (mask & IB_QP_PKEY_INDEX)
		qp->attr.pkey_index = attr->pkey_index;

	if (mask & IB_QP_PORT)
		qp->attr.port_num = attr->port_num;

	if (mask & IB_QP_QKEY)
		qp->attr.qkey = attr->qkey;

	if (mask & IB_QP_AV)
		vhost_rdma_init_av(dev, &attr->ah_attr, &qp->pri_av);

	if (mask & IB_QP_ALT_PATH) {
		vhost_rdma_init_av(dev, &attr->alt_ah_attr, &qp->alt_av);
		qp->attr.alt_port_num = attr->alt_port_num;
		qp->attr.alt_pkey_index = attr->alt_pkey_index;
		qp->attr.alt_timeout = attr->alt_timeout;
	}

	if (mask & IB_QP_PATH_MTU) {
		qp->attr.path_mtu = attr->path_mtu;
		qp->mtu = ib_mtu_enum_to_int(attr->path_mtu);
	}

	if (mask & IB_QP_TIMEOUT) {
		qp->attr.timeout = attr->timeout;
		if (attr->timeout == 0) {
			qp->qp_timeout_ticks = 0;
		} else {
			uint64_t ticks_per_us = rte_get_timer_hz() / 1000000;
			uint64_t j = (4096ULL << attr->timeout) / 1000 * ticks_per_us;
			qp->qp_timeout_ticks = j ? j : 1;
		}
	}

	if (mask & IB_QP_RETRY_CNT) {
		qp->attr.retry_cnt = attr->retry_cnt;
		qp->comp.retry_cnt = attr->retry_cnt;
		RDMA_LOG_INFO("qp#%d set retry count = %d", qp->qpn,
			 attr->retry_cnt);
	}

	if (mask & IB_QP_RNR_RETRY) {
		qp->attr.rnr_retry = attr->rnr_retry;
		qp->comp.rnr_retry = attr->rnr_retry;
		RDMA_LOG_INFO("qp#%d set rnr retry count = %d", qp->qpn,
			 attr->rnr_retry);
	}

	if (mask & IB_QP_RQ_PSN) {
		qp->attr.rq_psn = (attr->rq_psn & BTH_PSN_MASK);
		qp->resp.psn = qp->attr.rq_psn;
		RDMA_LOG_INFO("qp#%d set resp psn = 0x%x", qp->qpn,
			 qp->resp.psn);
	}

	if (mask & IB_QP_MIN_RNR_TIMER) {
		qp->attr.min_rnr_timer = attr->min_rnr_timer;
		RDMA_LOG_INFO("qp#%d set min rnr timer = 0x%x", qp->qpn,
			 attr->min_rnr_timer);
	}

	if (mask & IB_QP_SQ_PSN) {
		qp->attr.sq_psn = (attr->sq_psn & BTH_PSN_MASK);
		qp->req.psn = qp->attr.sq_psn;
		qp->comp.psn = qp->attr.sq_psn;
		RDMA_LOG_INFO("qp#%d set req psn = 0x%x", qp->qpn, qp->req.psn);
	}

	if (mask & IB_QP_PATH_MIG_STATE)
		qp->attr.path_mig_state = attr->path_mig_state;

	if (mask & IB_QP_DEST_QPN)
		qp->attr.dest_qp_num = attr->dest_qp_num;

	if (mask & IB_QP_STATE) {
		qp->attr.qp_state = attr->qp_state;

		switch (attr->qp_state) {
		case IB_QPS_RESET:
			RDMA_LOG_INFO("qp#%d state -> RESET", qp->qpn);
			// TODO: rxe_qp_reset(qp);
			break;

		case IB_QPS_INIT:
			RDMA_LOG_INFO("qp#%d state -> INIT", qp->qpn);
			qp->req.state = QP_STATE_INIT;
			qp->resp.state = QP_STATE_INIT;
			break;

		case IB_QPS_RTR:
			RDMA_LOG_INFO("qp#%d state -> RTR", qp->qpn);
			qp->resp.state = QP_STATE_READY;
			break;

		case IB_QPS_RTS:
			RDMA_LOG_INFO("qp#%d state -> RTS", qp->qpn);
			qp->req.state = QP_STATE_READY;
			break;

		case IB_QPS_SQD:
			RDMA_LOG_INFO("qp#%d state -> SQD", qp->qpn);
			// TODO: rxe_qp_drain(qp);
			break;

		case IB_QPS_SQE:
			RDMA_LOG_INFO("qp#%d state -> SQE !!?", qp->qpn);
			/* Not possible from modify_qp. */
			break;

		case IB_QPS_ERR:
			RDMA_LOG_INFO("qp#%d state -> ERR", qp->qpn);
			vhost_rdma_qp_error(qp);
			break;
		}
	}

	return 0;
}

void
vhost_rdma_qp_error(struct vhost_rdma_qp *qp)
{
	qp->req.state = QP_STATE_ERROR;
	qp->resp.state = QP_STATE_ERROR;
	qp->attr.qp_state = IB_QPS_ERR;

	/* drain work and packet queues */
	vhost_rdma_run_task(&qp->resp.task, 1);

	if (qp->type == IB_QPT_RC)
		vhost_rdma_run_task(&qp->comp.task, 1);
	else
		__vhost_rdma_do_task(&qp->comp.task);
	vhost_rdma_run_task(&qp->req.task, 1);
}
