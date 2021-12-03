/*
 * Vhost-user RDMA device demo: av
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
#include "vhost_rdma_ib.h"
#include "vhost_rdma_loc.h"

void vhost_rdma_av_to_attr(struct vhost_rdma_av *av,
							struct virtio_rdma_ah_attr *attr)
{
	struct virtio_rdma_global_route *grh = &attr->grh;

	rte_memcpy(grh->dgid.raw, av->grh.dgid.raw, sizeof(av->grh.dgid.raw));
	grh->flow_label = av->grh.flow_label;
	grh->sgid_index = av->grh.sgid_index;
	grh->hop_limit = av->grh.hop_limit;
	grh->traffic_class = av->grh.traffic_class;

	attr->port_num = 1;
}

void
vhost_rdma_av_from_attr(uint8_t port_num, struct vhost_rdma_av *av,
		     struct virtio_rdma_ah_attr *attr)
{
	const struct virtio_rdma_global_route *grh = &attr->grh;

	memset(av, 0, sizeof(*av));
	rte_memcpy(av->grh.dgid.raw, grh->dgid.raw, sizeof(grh->dgid.raw));
	av->grh.flow_label = grh->flow_label;
	av->grh.sgid_index = grh->sgid_index;
	av->grh.hop_limit = grh->hop_limit;
	av->grh.traffic_class = grh->traffic_class;
	av->port_num = port_num;
}

void
vhost_rdma_av_fill_ip_info(struct vhost_rdma_dev *dev,
			struct vhost_rdma_av *av, struct virtio_rdma_ah_attr *attr)
{
	const struct vhost_rdma_gid *sgid_attr;
	int ibtype;
	int type;

	sgid_attr = &dev->gid_tbl[attr->grh.sgid_index];

	rdma_gid2ip((struct sockaddr *)&av->sgid_addr, &sgid_attr->gid);
	rdma_gid2ip((struct sockaddr *)&av->dgid_addr,
			&attr->grh.dgid);

	ibtype = rdma_gid_attr_network_type(sgid_attr);

	switch (ibtype) {
	case RDMA_NETWORK_IPV4:
		type = VHOST_NETWORK_TYPE_IPV4;
		break;
	case RDMA_NETWORK_IPV6:
		type = VHOST_NETWORK_TYPE_IPV6;
		break;
	default:
		/* not reached - checked in av_chk_attr */
		type = 0;
		break;
	}

	av->network_type = type;
}

void
vhost_rdma_init_av(struct vhost_rdma_dev *dev, struct virtio_rdma_ah_attr *attr,
				struct vhost_rdma_av *av)
{
	vhost_rdma_av_from_attr(attr->port_num, av, attr);
	vhost_rdma_av_fill_ip_info(dev, av, attr);
	rte_memcpy(av->dmac, attr->roce.dmac, ETH_ALEN);
}

int
vhost_rdma_av_chk_attr(struct vhost_rdma_dev *dev,
						struct virtio_rdma_ah_attr *attr)
{
	struct virtio_rdma_global_route *grh = &attr->grh;
	int type;

	if (attr->ah_flags & IB_AH_GRH) {
		// uint8 sgid_index is always smaller than VHOST_MAX_GID_TBL_LEN
		type = rdma_gid_attr_network_type(&dev->gid_tbl[grh->sgid_index]);
		if (type < RDMA_NETWORK_IPV4 ||
			type > RDMA_NETWORK_IPV6) {
			RDMA_LOG_ERR("invalid network type = %d", type);
			return -EINVAL;
		}
	}

	return 0;
}

void
init_av_from_virtio(struct vhost_rdma_dev *dev, struct vhost_rdma_av *dst,
			const struct virtio_rdma_av *src)
{
	struct vhost_rdma_gid *sgid;

	sgid = &dev->gid_tbl[src->gid_index];

	dst->port_num = src->port;
	rdma_gid2ip((struct sockaddr *)&dst->sgid_addr, &sgid->gid);
	rdma_gid2ip((struct sockaddr *)&dst->dgid_addr, (union ib_gid *)&src->dgid);
	rte_memcpy(&dst->grh.dgid, (union ib_gid *)&src->dgid, 16);
	dst->grh.flow_label = src->sl_tclass_flowlabel;
	dst->grh.hop_limit = src->hop_limit;
	dst->grh.sgid_index = src->gid_index;
	dst->grh.traffic_class = src->sl_tclass_flowlabel >> 20;
	rte_memcpy(dst->dmac, src->dmac, 6);
	if (ipv6_addr_v4mapped((struct in6_addr *)src->dgid)) {
		dst->network_type = VHOST_NETWORK_TYPE_IPV4;
	} else {
		dst->network_type = VHOST_NETWORK_TYPE_IPV6;
	}
}

struct vhost_rdma_av*
vhost_rdma_get_av(struct vhost_rdma_pkt_info *pkt)
{
	if (!pkt || !pkt->qp)
		return NULL;

	if (pkt->qp->type == IB_QPT_RC || pkt->qp->type == IB_QPT_UC)
		return &pkt->qp->pri_av;

	return (pkt->wqe) ? &pkt->wqe->av : NULL;
}
