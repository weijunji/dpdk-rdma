/*
 * Vhost-user RDMA device demo: task completer
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

#include <rte_mbuf.h>

#include "vhost_rdma_loc.h"

void
retransmit_timer(__rte_unused struct rte_timer *timer, void* arg)
{
	struct vhost_rdma_qp *qp = arg;

	if (qp->valid) {
		qp->comp.timeout = 1;
		vhost_rdma_run_task(&qp->comp.task, 1);
	}
}

void
vhost_rdma_comp_queue_pkt(struct vhost_rdma_qp *qp, struct rte_mbuf *mbuf)
{
	int must_sched;

	if (unlikely(rte_ring_enqueue(qp->resp_pkts, mbuf) != 0)) {
		rte_pktmbuf_free(mbuf);
	}

	must_sched = rte_ring_count(qp->resp_pkts) > 1;
	if (must_sched != 0)
		vhost_rdma_counter_inc(MBUF_TO_PKT(mbuf)->dev,
								VHOST_CNT_COMPLETER_SCHED);

	vhost_rdma_run_task(&qp->comp.task, must_sched);
}

int
vhost_rdma_completer(__rte_unused void* arg)
{
	return -EAGAIN;
}
