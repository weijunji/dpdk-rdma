/*
 * Vhost-user RDMA device demo: init and packets forwarding
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

#include <signal.h>
#include <getopt.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "vhost_rdma.h"
#include "vhost_rdma_hdr.h"

#define RTE_LOGTYPE_ETHER RTE_LOGTYPE_USER1

#define LOG_DEBUG_DP(f, ...) RTE_LOG_DP(DEBUG, ETHER, f "\n", ##__VA_ARGS__)
#define LOG_INFO_DP(f, ...) RTE_LOG_DP(INFO, ETHER, f "\n", ##__VA_ARGS__)
#define LOG_WARN_DP(f, ...) RTE_LOG_DP(WARNING, ETHER, f "\n", ##__VA_ARGS__)
#define LOG_ERR_DP(f, ...) RTE_LOG_DP(ERR, ETHER, f "\n", ##__VA_ARGS__)

#define LOG_DEBUG(f, ...) RTE_LOG(DEBUG, ETHER, f "\n", ##__VA_ARGS__)
#define LOG_INFO(f, ...) RTE_LOG(INFO, ETHER, f "\n", ##__VA_ARGS__)
#define LOG_WARN(f, ...) RTE_LOG(WARNING, ETHER, f "\n", ##__VA_ARGS__)
#define LOG_ERR(f, ...) RTE_LOG(ERR, ETHER, f "\n", ##__VA_ARGS__)

#define MAX_PKTS_BURST 32

static struct rte_eth_conf port_conf_default;
static struct rte_eth_conf port_conf_offload = {
	.txmode = {
		.offloads = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM,
	},
};

static struct rte_mempool *mbuf_pool;

static struct rte_ring* rdma_rx_ring;
static struct rte_ring* rdma_tx_ring;

static char dev_pathname[PATH_MAX] = "/tmp/vhost-rdma0";

uint16_t vhost_port_id, pair_port_id;

volatile bool force_quit;

struct udpv4_hdr {
	struct rte_ether_hdr ether;
	struct rte_ipv4_hdr ipv4;
	struct rte_udp_hdr udp;
} __rte_aligned(2);

struct udpv6_hdr {
	struct rte_ether_hdr ether;
	struct rte_ipv6_hdr ipv6;
	struct rte_udp_hdr udp;
} __rte_aligned(2);

static __rte_always_inline void
rdma_rx_one(struct rte_mbuf *pkt) {
	if (unlikely(rte_ring_enqueue(rdma_rx_ring, pkt) != 0)) {
		rte_pktmbuf_free(pkt);
		LOG_DEBUG_DP("rdma rx drop one pkt");
	}
}

/*
 * there is no need to change mac address of pkts,
 * because the pair dev is transparent
 */

/* vhost --> pair_dev */
static __rte_always_inline void
eth_rx() {
	struct rte_mbuf *pkts[MAX_PKTS_BURST];
	uint16_t nb_rx_pkts, nb_tx_pkts;

	/* send ethernet pkts */
	nb_rx_pkts = rte_eth_rx_burst(vhost_port_id, 0, pkts, MAX_PKTS_BURST);
	if (nb_rx_pkts != 0) {
		#ifdef DEBUG_ETHERNET
		LOG_DEBUG("rx got %d packets", nb_rx_pkts);
		for (int i = 0; i < nb_rx_pkts; i++) {
			struct rte_ether_hdr *eth;
			char sbuf[RTE_ETHER_ADDR_FMT_SIZE];
			char dbuf[RTE_ETHER_ADDR_FMT_SIZE];
			eth = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
			rte_ether_format_addr(sbuf, RTE_ETHER_ADDR_FMT_SIZE, &eth->s_addr);
			rte_ether_format_addr(dbuf, RTE_ETHER_ADDR_FMT_SIZE, &eth->d_addr);
			LOG_DEBUG(" -> : 0x%x %s %s", rte_be_to_cpu_16(eth->ether_type), sbuf, dbuf);
		}
		#endif

		// set l4_len to let dpdk tap calculate correct cksum
		for (int i = 0; i < nb_rx_pkts; i++) {
			if ((pkts[i]->ol_flags & PKT_TX_L4_MASK) == PKT_TX_TCP_CKSUM) {
				pkts[i]->l4_len = sizeof(struct rte_tcp_hdr);
			}

			if ((pkts[i]->ol_flags & PKT_TX_L4_MASK) == PKT_TX_UDP_CKSUM) {
				pkts[i]->l4_len = sizeof(struct rte_udp_hdr);
			}
		}

		nb_tx_pkts = rte_eth_tx_burst(pair_port_id, 0, pkts, nb_rx_pkts);
		if (unlikely(nb_tx_pkts < nb_rx_pkts)) {
			uint16_t buf;

			for (buf = nb_tx_pkts; buf < nb_rx_pkts; buf++)
				rte_pktmbuf_free(pkts[buf]);
			LOG_DEBUG_DP("rx drop %d pkts", nb_rx_pkts - nb_tx_pkts);
		}
	}

	/* send rdma pkts */
	nb_rx_pkts = rte_ring_dequeue_burst(rdma_tx_ring, (void**)pkts,
										MAX_PKTS_BURST, NULL);
	if (nb_rx_pkts != 0) {
		LOG_DEBUG_DP("rx got %d rdma packets", nb_rx_pkts);

		nb_tx_pkts = rte_eth_tx_burst(pair_port_id, 0, pkts, nb_rx_pkts);
		if (unlikely(nb_tx_pkts < nb_rx_pkts)) {
			uint16_t buf;

			for (buf = nb_tx_pkts; buf < nb_rx_pkts; buf++)
				rte_pktmbuf_free(pkts[buf]);
			LOG_DEBUG_DP("rx drop %d rdma pkts", nb_rx_pkts - nb_tx_pkts);
		}
	}
}

/*
 * pair_dev --> vhost
 * WARNING: ip reassemble is NOT supported now
 */
static __rte_always_inline void
eth_tx() {
	struct rte_mbuf *pkts[MAX_PKTS_BURST];
	uint16_t nb_rx_pkts;
	struct udpv4_hdr *udpv4;
	struct udpv6_hdr *udpv6;

	nb_rx_pkts = rte_eth_rx_burst(pair_port_id, 0, pkts, MAX_PKTS_BURST);
	if (nb_rx_pkts == 0) {
		return;
	}

	#ifdef DEBUG_ETHERNET
	LOG_DEBUG("tx got %d packets", nb_rx_pkts);
	for (int i = 0; i < nb_rx_pkts; i++) {
		struct rte_ether_hdr *eth;
		char sbuf[RTE_ETHER_ADDR_FMT_SIZE];
		char dbuf[RTE_ETHER_ADDR_FMT_SIZE];
		eth = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
		rte_ether_format_addr(sbuf, RTE_ETHER_ADDR_FMT_SIZE, &eth->s_addr);
		rte_ether_format_addr(dbuf, RTE_ETHER_ADDR_FMT_SIZE, &eth->d_addr);
		LOG_DEBUG(" <- : 0x%x %s %s", rte_be_to_cpu_16(eth->ether_type), sbuf, dbuf);
	}
	#endif

	/* check if pkt is rocev2 */
	for (int i = 0; i < nb_rx_pkts; i++) {
		udpv4 = rte_pktmbuf_mtod(pkts[i], struct udpv4_hdr *);
		if (rte_be_to_cpu_16(udpv4->ether.ether_type) == RTE_ETHER_TYPE_IPV4 &&
		    udpv4->ipv4.next_proto_id == IPPROTO_UDP &&
			udpv4->udp.dst_port == htons(ROCE_V2_UDP_DPORT)) {
			rdma_rx_one(pkts[i]);
			continue;
		}

		udpv6 = rte_pktmbuf_mtod(pkts[i], struct udpv6_hdr *);
		if (rte_be_to_cpu_16(udpv6->ether.ether_type) == RTE_ETHER_TYPE_IPV6 &&
		    udpv6->ipv6.proto == IPPROTO_UDP &&
			udpv6->udp.dst_port == htons(ROCE_V2_UDP_DPORT)) {
			rdma_rx_one(pkts[i]);
			continue;
		}

		/* forward pkt to vhost_net */
		if (unlikely(rte_eth_tx_burst(vhost_port_id, 0, &pkts[i], 1) != 1)) {
			rte_pktmbuf_free(pkts[i]);
			LOG_DEBUG_DP("tx drop one pkt");
		}
	}
}

static int
eth_main_loop(__rte_unused void* arg) {
	LOG_INFO("ethernet main loop started");
	while (!force_quit) {
		eth_rx();

		eth_tx();
	}
	LOG_INFO("ethernet main loop quit");
	return 0;
}

static __rte_noreturn void
signal_handler(__rte_unused int signum)
{
	// close dev to destroy vhost sock file
	force_quit = true;
    vhost_rdma_destroy(dev_pathname);
	rte_eth_dev_close(vhost_port_id);
	rte_exit(0, "Exiting on signal_handler\n");
}

static int
init_port(uint16_t port_id, bool offload) {
	int ret;
	uint16_t nb_rxd = 1024;
	uint16_t nb_txd = 1024;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_ether_addr addr;
	struct rte_eth_conf port_conf = offload ? port_conf_offload: port_conf_default;
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret < 0)
		goto out;

	ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
	if (ret < 0)
		goto out;

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
	if (ret < 0)
		goto out;

	ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
				rte_eth_dev_socket_id(port_id), NULL,
				mbuf_pool);
	if (ret < 0)
		goto out;

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
				rte_eth_dev_socket_id(port_id), &txconf);
	if (ret < 0)
		goto out;

	ret = rte_eth_dev_start(port_id);
	if (ret < 0)
		goto out;

	ret = rte_eth_promiscuous_enable(port_id);
	if (ret < 0)
		goto out;

	ret = rte_eth_macaddr_get(port_id, &addr);
	if (ret < 0)
		goto out;

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &addr);
	LOG_INFO("port %d MAC %s", port_id, buf);

out:
	return ret;
}

static int
parse_args(int argc, char **argv)
{
	int opt;
	int option_index;
	static struct option lgopts[] = {
		{"sock-path", required_argument, 0, 256},
		{NULL, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "s:",
				lgopts, &option_index)) != EOF) {
		switch (opt) {
		/* socket path */
		case 's':
		case 256:
			rte_strscpy(dev_pathname, optarg, PATH_MAX);
			break;

		default:
			LOG_ERR("unknown option");
			return -1;
		}
	}

	return 0;
}

int
main(int argc, char **argv)
{
	int ret;
	uint16_t port_id;
	struct rte_eth_dev_info dev_info;
	bool vhost_found = false;
	bool pair_found = false;

	signal(SIGINT, signal_handler);

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	rte_log_set_global_level(RTE_LOG_NOTICE);
	#ifdef DEBUG_ETHERNET
	rte_log_set_global_level(RTE_LOG_DEBUG);
	rte_log_set_level_pattern("lib.vhost.*", RTE_LOG_NOTICE);
	rte_log_set_level(RTE_LOGTYPE_ETHER, RTE_LOG_DEBUG);
	#endif
	#ifdef DEBUG_RDMA
	rte_log_set_global_level(RTE_LOG_DEBUG);
	rte_log_set_level_pattern("lib.vhost.*", RTE_LOG_NOTICE);
	rte_log_set_level(RTE_LOGTYPE_RDMA, RTE_LOG_DEBUG);
	#endif

	argc -= ret;
	argv += ret;

	if (parse_args(argc, argv) != 0) {
		rte_exit(EXIT_FAILURE, "failed to parse args\n");
	}

	if (rte_lcore_count() < 2) {
		rte_exit(EXIT_FAILURE,
		"Not enough cores, expecting at least 2\n"
		"\tcore 0:   ethernet packages forwarding\n"
		"\tcore 1-n: rdma ctrl thread\n"
		);
	}

	/* init mempool */
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 65535,
			250, sizeof(struct vhost_rdma_pkt_info), RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

	/* init rdma tx/rx ring */
	rdma_rx_ring = rte_ring_create("rdma_rx_ring", 1024, rte_socket_id(),
									RING_F_SP_ENQ | RING_F_MC_HTS_DEQ);
	if (rdma_rx_ring == NULL)
		rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

	rdma_tx_ring = rte_ring_create("rdma_tx_ring", 1024, rte_socket_id(),
									RING_F_MP_HTS_ENQ | RING_F_SC_DEQ);
	if (rdma_tx_ring == NULL)
		rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

	/* init eth_dev */
	RTE_ETH_FOREACH_DEV(port_id) {
		rte_eth_dev_info_get(port_id, &dev_info);

		if (!vhost_found && strcmp(dev_info.driver_name, "net_vhost") == 0) {
			vhost_port_id = port_id;
			vhost_found = true;
			if (init_port(port_id, false) != 0) {
				rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
			}
			LOG_INFO("use %s(%d) as vhost dev", dev_info.device->name, port_id);
		} else if (!pair_found && strcmp(dev_info.driver_name, "net_tap") == 0) {
			pair_port_id = port_id;
			pair_found = true;
			if (init_port(port_id, true) != 0) {
				rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
			}
			LOG_INFO("use %s(%d) as pair dev", dev_info.device->name, port_id);
		}
	}

	if (!vhost_found)
		rte_exit(EXIT_FAILURE, "vhost dev not found");
	if (!pair_found)
		rte_exit(EXIT_FAILURE, "tap dev not found");

	/* init vhost rdma */
	vhost_rdma_construct(dev_pathname, pair_port_id, mbuf_pool, rdma_tx_ring, rdma_rx_ring);

	rte_vhost_driver_start(dev_pathname);

	/* launch ether main loop to forward pkts */
	eth_main_loop(NULL);

	rte_eal_mp_wait_lcore();

	rte_eal_cleanup();

	return 0;
}
