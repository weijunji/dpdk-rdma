project('dpdk-rdma', 'c',
  version : '0.1',
  default_options : [
    'warning_level=3',
    'werror=True'
  ]
)

dpdk = dependency('libdpdk')

executable('dpdk-rdma',
  [
    'main.c',
    'verbs.c',
    'vhost_user.c',
    'vhost_rdma.c',
    'vhost_rdma_ib.c',
    'vhost_rdma_pool.c',
    'vhost_rdma_mr.c',
    'vhost_rdma_qp.c',
    'vhost_rdma_av.c',
  ],
  dependencies: dpdk,
  c_args: [
    '-DALLOW_EXPERIMENTAL_API',
    '-DDEBUG_RDMA'
  ],
  install : false
)
