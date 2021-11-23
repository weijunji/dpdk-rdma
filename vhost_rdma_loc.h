/*
 * Vhost-user RDMA device demo: loc header
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

#ifndef __VHOST_RDMA_LOC_H__
#define __VHOST_RDMA_LOC_H__

#include <stdint.h>

#include "vhost_rdma_ib.h"

/* vhost_rdma_mr.c */
uint8_t vhost_rdma_get_next_key(uint32_t last_key);
void vhost_rdma_mr_init_key(struct vhost_rdma_mr *mr, uint32_t mrn);

#endif
