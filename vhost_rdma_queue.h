/*
 * Vhost-user RDMA device demo: sq/rq queue and intr handler
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

#ifndef __VHOST_RDMA_QUEUE_H__
#define __VHOST_RDMA_QUEUE_H__

#include <stdint.h>

#include <rte_interrupts.h>

#include "vhost_rdma_ib.h"

enum queue_type {
	VHOST_RDMA_QUEUE_SQ,
	VHOST_RDMA_QUEUE_RQ,
};

/*
 *             ---|---- 1 ----|---- 2 ----|- 0 -
 * avail ring: |-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|
 *                ^           ^           ^
 *           last_avail    producer   avail->idx
 *            consumer
 * area 0: not avail
 * area 1: prepared buf, can be used by task
 * area 2: avail but not prepared, will be prepared in handle_sq/rq()
 */
struct vhost_rdma_queue {
	struct vhost_queue *vq;
	void* data;
	size_t elem_size;
	size_t num_elems; 
	uint16_t consumer_index;
	uint16_t producer_index;

	struct rte_intr_handle intr_handle;
	rte_intr_callback_fn cb;
};

struct vhost_rdma_cq;

int vhost_rdma_queue_init(struct vhost_rdma_qp *qp, struct vhost_rdma_queue* queue, char* name,
			struct vhost_queue* vq, size_t elem_size, enum queue_type type);
void vhost_rdma_queue_cleanup(struct vhost_rdma_queue* queue);
int vhost_rdma_cq_post(struct vhost_rdma_dev *dev, struct vhost_rdma_cq *cq,
				struct virtio_rdma_cqe *cqe, int solicited);

static __rte_always_inline void*
vhost_rdma_queue_get_data(struct vhost_rdma_queue* queue, size_t idx)
{
	return queue->data + queue->elem_size * idx;
}

static __rte_always_inline bool queue_empty(struct vhost_rdma_queue *q)
{
	uint16_t prod;
	uint16_t cons;

	prod = q->producer_index;
	cons = q->consumer_index;

	return ((prod - cons) & (q->num_elems - 1)) == 0;
}

static __rte_always_inline void*
consumer_addr(struct vhost_rdma_queue *q)
{
	uint16_t cons;
	uint16_t desc_idx;
	
	assert(q->consumer_index == q->vq->last_avail_idx);

	cons = q->consumer_index & (q->num_elems - 1);
	desc_idx = q->vq->vring.avail->ring[cons];

	return vhost_rdma_queue_get_data(q, desc_idx);
}

static __rte_always_inline void*
addr_from_index(struct vhost_rdma_queue *q, unsigned int index)
{
	uint16_t cons;
	uint16_t desc_idx;

	cons = index & (q->num_elems - 1);
	desc_idx = q->vq->vring.avail->ring[cons];

	return vhost_rdma_queue_get_data(q, desc_idx);
}

static __rte_always_inline void*
queue_head(struct vhost_rdma_queue *q)
{
	return queue_empty(q) ? NULL : consumer_addr(q);
}

static __rte_always_inline void
advance_consumer(struct vhost_rdma_queue *q)
{
	uint16_t cons;
	uint16_t desc;

	assert(q->consumer_index == q->vq->last_avail_idx);

	cons = q->consumer_index & (q->num_elems - 1);

	desc = q->vq->vring.avail->ring[cons];

	vhost_queue_push(q->vq, desc, 0);

	q->consumer_index++;
	q->vq->last_avail_idx++;
}

#endif
