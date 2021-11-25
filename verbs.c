/*
 * Vhost-user RDMA device demo: ib verbs, copy from kernel
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

#include "verbs.h"

static const struct {
	int			valid;
	enum ib_qp_attr_mask	req_param[IB_QPT_MAX];
	enum ib_qp_attr_mask	opt_param[IB_QPT_MAX];
} qp_state_table[IB_QPS_ERR + 1][IB_QPS_ERR + 1] = {
	[IB_QPS_RESET] = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_INIT]  = {
			.valid = 1,
			.req_param = {
				[IB_QPT_UD]  = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_QKEY),
				[IB_QPT_UC]  = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_RC]  = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_SMI] = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
			}
		},
	},
	[IB_QPS_INIT]  = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 },
		[IB_QPS_INIT]  = {
			.valid = 1,
			.opt_param = {
				[IB_QPT_UD]  = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_QKEY),
				[IB_QPT_UC]  = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_RC]  = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_SMI] = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
			}
		},
		[IB_QPS_RTR]   = {
			.valid = 1,
			.req_param = {
				[IB_QPT_UC]  = (IB_QP_AV			|
						IB_QP_PATH_MTU			|
						IB_QP_DEST_QPN			|
						IB_QP_RQ_PSN),
				[IB_QPT_RC]  = (IB_QP_AV			|
						IB_QP_PATH_MTU			|
						IB_QP_DEST_QPN			|
						IB_QP_RQ_PSN			|
						IB_QP_MAX_DEST_RD_ATOMIC	|
						IB_QP_MIN_RNR_TIMER),
			},
			.opt_param = {
				 [IB_QPT_UD]  = (IB_QP_PKEY_INDEX		|
						 IB_QP_QKEY),
				 [IB_QPT_UC]  = (IB_QP_ALT_PATH			|
						 IB_QP_ACCESS_FLAGS		|
						 IB_QP_PKEY_INDEX),
				 [IB_QPT_RC]  = (IB_QP_ALT_PATH			|
						 IB_QP_ACCESS_FLAGS		|
						 IB_QP_PKEY_INDEX),
				 [IB_QPT_SMI] = (IB_QP_PKEY_INDEX		|
						 IB_QP_QKEY),
				 [IB_QPT_GSI] = (IB_QP_PKEY_INDEX		|
						 IB_QP_QKEY),
			 },
		},
	},
	[IB_QPS_RTR]   = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 },
		[IB_QPS_RTS]   = {
			.valid = 1,
			.req_param = {
				[IB_QPT_UD]  = IB_QP_SQ_PSN,
				[IB_QPT_UC]  = IB_QP_SQ_PSN,
				[IB_QPT_RC]  = (IB_QP_TIMEOUT			|
						IB_QP_RETRY_CNT			|
						IB_QP_RNR_RETRY			|
						IB_QP_SQ_PSN			|
						IB_QP_MAX_QP_RD_ATOMIC),
				[IB_QPT_SMI] = IB_QP_SQ_PSN,
				[IB_QPT_GSI] = IB_QP_SQ_PSN,
			},
			.opt_param = {
				 [IB_QPT_UD]  = (IB_QP_CUR_STATE		|
						 IB_QP_QKEY),
				 [IB_QPT_UC]  = (IB_QP_CUR_STATE		|
						 IB_QP_ALT_PATH			|
						 IB_QP_ACCESS_FLAGS		|
						 IB_QP_PATH_MIG_STATE),
				 [IB_QPT_RC]  = (IB_QP_CUR_STATE		|
						 IB_QP_ALT_PATH			|
						 IB_QP_ACCESS_FLAGS		|
						 IB_QP_MIN_RNR_TIMER		|
						 IB_QP_PATH_MIG_STATE),
				 [IB_QPT_SMI] = (IB_QP_CUR_STATE		|
						 IB_QP_QKEY),
				 [IB_QPT_GSI] = (IB_QP_CUR_STATE		|
						 IB_QP_QKEY),
			 }
		}
	},
	[IB_QPS_RTS]   = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 },
		[IB_QPS_RTS]   = {
			.valid = 1,
			.opt_param = {
				[IB_QPT_UD]  = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_UC]  = (IB_QP_CUR_STATE			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_ALT_PATH			|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_RC]  = (IB_QP_CUR_STATE			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_ALT_PATH			|
						IB_QP_PATH_MIG_STATE		|
						IB_QP_MIN_RNR_TIMER),
				[IB_QPT_SMI] = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
			}
		},
		[IB_QPS_SQD]   = {
			.valid = 1,
			.opt_param = {
				[IB_QPT_UD]  = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_UC]  = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_RC]  = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_SMI] = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_GSI] = IB_QP_EN_SQD_ASYNC_NOTIFY
			}
		},
	},
	[IB_QPS_SQD]   = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 },
		[IB_QPS_RTS]   = {
			.valid = 1,
			.opt_param = {
				[IB_QPT_UD]  = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_UC]  = (IB_QP_CUR_STATE			|
						IB_QP_ALT_PATH			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_RC]  = (IB_QP_CUR_STATE			|
						IB_QP_ALT_PATH			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_MIN_RNR_TIMER		|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_SMI] = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
			}
		},
		[IB_QPS_SQD]   = {
			.valid = 1,
			.opt_param = {
				[IB_QPT_UD]  = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
				[IB_QPT_UC]  = (IB_QP_AV			|
						IB_QP_ALT_PATH			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_PKEY_INDEX		|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_RC]  = (IB_QP_PORT			|
						IB_QP_AV			|
						IB_QP_TIMEOUT			|
						IB_QP_RETRY_CNT			|
						IB_QP_RNR_RETRY			|
						IB_QP_MAX_QP_RD_ATOMIC		|
						IB_QP_MAX_DEST_RD_ATOMIC	|
						IB_QP_ALT_PATH			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_PKEY_INDEX		|
						IB_QP_MIN_RNR_TIMER		|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_SMI] = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
			}
		}
	},
	[IB_QPS_SQE]   = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 },
		[IB_QPS_RTS]   = {
			.valid = 1,
			.opt_param = {
				[IB_QPT_UD]  = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_UC]  = (IB_QP_CUR_STATE			|
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_SMI] = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
			}
		}
	},
	[IB_QPS_ERR] = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 }
	}
};

bool ib_modify_qp_is_ok(enum ib_qp_state cur_state, enum ib_qp_state next_state,
			enum ib_qp_type type, enum ib_qp_attr_mask mask)
{
	enum ib_qp_attr_mask req_param, opt_param;

	if (mask & IB_QP_CUR_STATE  &&
	    cur_state != IB_QPS_RTR && cur_state != IB_QPS_RTS &&
	    cur_state != IB_QPS_SQD && cur_state != IB_QPS_SQE)
		return false;

	if (!qp_state_table[cur_state][next_state].valid)
		return false;

	req_param = qp_state_table[cur_state][next_state].req_param[type];
	opt_param = qp_state_table[cur_state][next_state].opt_param[type];

	if ((mask & req_param) != req_param)
		return false;

	if (mask & ~(req_param | opt_param | IBV_QP_STATE))
		return false;

	return true;
}
