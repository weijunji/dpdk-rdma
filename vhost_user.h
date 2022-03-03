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

#ifndef __VHOST_USER_SPEC_H__
#define __VHOST_USER_SPEC_H__

#include <linux/vhost_types.h>
#include <sys/uio.h>

#include <rte_vhost.h>

#define VHOST_USER_MEMORY_MAX_NREGIONS		8
#define VHOST_USER_MAX_CONFIG_SIZE		256

enum vhost_user_request {
	VHOST_USER_NONE = 0,
	VHOST_USER_GET_FEATURES = 1,
	VHOST_USER_SET_FEATURES = 2,
	VHOST_USER_SET_OWNER = 3,
	VHOST_USER_RESET_OWNER = 4,
	VHOST_USER_SET_MEM_TABLE = 5,
	VHOST_USER_SET_LOG_BASE = 6,
	VHOST_USER_SET_LOG_FD = 7,
	VHOST_USER_SET_VRING_NUM = 8,
	VHOST_USER_SET_VRING_ADDR = 9,
	VHOST_USER_SET_VRING_BASE = 10,
	VHOST_USER_GET_VRING_BASE = 11,
	VHOST_USER_SET_VRING_KICK = 12,
	VHOST_USER_SET_VRING_CALL = 13,
	VHOST_USER_SET_VRING_ERR = 14,
	VHOST_USER_GET_PROTOCOL_FEATURES = 15,
	VHOST_USER_SET_PROTOCOL_FEATURES = 16,
	VHOST_USER_GET_QUEUE_NUM = 17,
	VHOST_USER_SET_VRING_ENABLE = 18,
	VHOST_USER_GET_CONFIG = 24,
	VHOST_USER_SET_CONFIG = 25,
	VHOST_USER_MAX
};

/** Get/set config msg payload */
struct vhost_user_config {
	uint32_t offset;
	uint32_t size;
	uint32_t flags;
	uint8_t region[VHOST_USER_MAX_CONFIG_SIZE];
};

/** Fixed-size vhost_memory struct */
struct vhost_memory_padded {
	uint32_t nregions;
	uint32_t padding;
	struct vhost_memory_region regions[VHOST_USER_MEMORY_MAX_NREGIONS];
};

struct vhost_user_msg {
	enum vhost_user_request request;

#define VHOST_USER_VERSION_MASK     0x3
#define VHOST_USER_REPLY_MASK       (0x1 << 2)
	uint32_t flags;
	uint32_t size; /**< the following payload size */
	union {
#define VHOST_USER_VRING_IDX_MASK   0xff
#define VHOST_USER_VRING_NOFD_MASK  (0x1 << 8)
		uint64_t u64;
		struct vhost_vring_state state;
		struct vhost_vring_addr addr;
		struct vhost_memory_padded memory;
		struct vhost_user_config cfg;
	} payload;
} __rte_packed;

struct vhost_queue {
	struct rte_vhost_vring vring;

	uint16_t last_avail_idx;
	uint16_t last_used_idx;
	uint16_t id;

	bool enabled;
};

static __rte_always_inline uint16_t
vq_get_desc_idx(struct vhost_queue *vq)
{
	uint16_t desc_idx;
	uint16_t last_avail_idx;

	last_avail_idx = vq->last_avail_idx & (vq->vring.size - 1);
	desc_idx = vq->vring.avail->ring[last_avail_idx];
	vq->last_avail_idx++;

	return desc_idx;
}

static __rte_always_inline void
vhost_queue_notify(int vid, struct vhost_queue* vq) {
	rte_vhost_vring_call(vid, vq->id);
}

static __rte_always_inline uint64_t
gpa_to_vva(struct rte_vhost_memory *mem, uint64_t gpa, uint64_t *len)
{
	assert(mem != NULL);
	return rte_vhost_va_from_guest_pa(mem, gpa, len);
}

static __rte_always_inline bool
descriptor_has_next_split(struct vring_desc *cur_desc)
{
	return !!(cur_desc->flags & VRING_DESC_F_NEXT);
}

static __rte_always_inline struct vring_desc *
vring_get_next_desc(struct vring_desc *table, struct vring_desc *desc)
{
	if (desc->flags & VRING_DESC_F_NEXT)
		return &table[desc->next];

	return NULL;
}

static __rte_always_inline bool
vhost_vq_is_avail(struct vhost_queue *vq)
{
	return vq->vring.avail->idx != vq->last_avail_idx;
}

static __rte_always_inline void
vhost_queue_push(struct vhost_queue *vq, uint16_t idx, uint32_t len)
{
	struct vring_used *used = vq->vring.used;

	used->ring[used->idx & (vq->vring.size - 1)].id = idx;
	used->ring[used->idx & (vq->vring.size - 1)].len = len;
	rte_smp_mb();
	used->idx++;
	rte_smp_mb();
}

int setup_iovs_from_descs(struct rte_vhost_memory *mem, struct vhost_queue *vq,
				uint16_t req_idx, struct iovec *iovs, uint16_t num_iovs,
				uint16_t *num_in, uint16_t* num_out);

#endif
