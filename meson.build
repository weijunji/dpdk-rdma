project('dpdk-rdma', 'c',
  version : '0.1',
  default_options : [
    'warning_level=2',
    'werror=True',
  ]
)

dpdk = dependency('libdpdk')

executable('dpdk-rdma',
  [
    'main.c',
    'verbs.c',
    'vhost_net.c',
    'vhost_user.c',
    'vhost_rdma.c',
    'vhost_rdma_ib.c',
    'vhost_rdma_pool.c',
    'vhost_rdma_mr.c',
    'vhost_rdma_qp.c',
    'vhost_rdma_av.c',
    'vhost_rdma_task.c',
    'vhost_rdma_queue.c',
    'vhost_rdma_opcode.c',
    'vhost_rdma_net.c',
    'vhost_rdma_comp.c',
    'vhost_rdma_resp.c',
    'vhost_rdma_recv.c',
    'vhost_rdma_crc.c',
    'vhost_rdma_req.c',
  ],
  dependencies: dpdk,
  c_args: [
    '-DALLOW_EXPERIMENTAL_API',
  ],
  install : false
)
