/*
 * Vhost-user RDMA device demo: vhost-user spec
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

#include "vhost_rdma.h"
#include "vhost_user.h"

static uint16_t
vq_get_desc_idx(struct vhost_queue *vq)
{
	uint16_t desc_idx;
	uint16_t last_avail_idx;

	last_avail_idx = vq->last_avail_idx & (vq->vring.size - 1);
	desc_idx = vq->vring.avail->ring[last_avail_idx];
	vq->last_avail_idx++;

	return desc_idx;
}
