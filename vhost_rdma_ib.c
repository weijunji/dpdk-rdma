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

#include "vhost_rdma.h"
#include "vhost_rdma_ib.h"

void
vhost_rdma_handle_ctrl(void* arg) {
	struct vhost_rdma_dev* dev = arg;
	int kick_fd, nbytes;
	uint64_t buf;

	RDMA_LOG_INFO("rdma ctrl kick");
	kick_fd = dev->vqs[0].vring.kickfd;
	do {
		nbytes = read(kick_fd, &buf, 8);
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
}
