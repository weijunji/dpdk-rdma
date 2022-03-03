# DPDK RDMA

A demo of virtio-net-roce

## Build

* Download and install dpdk (we only tested with dpdk-stable-20.11.3).

* Build dpdk-rdma
```bash
mkdir build
meson build
cd build
ninja
```

## Run

* Start dpdk-rdma
```bash
ninja && sudo ./dpdk-rdma --vdev 'net_tap0' --lcore '1-3'
```

* Run vm with following arguments using libvirt
```xml
<qemu:commandline>
    <qemu:arg value='-chardev'/>
    <qemu:arg value='socket,path=/tmp/vhost-rdma0,id=vurdma'/>
    <qemu:arg value='-device'/>
    <qemu:arg value='vhost-user-rdma-pci,page-per-vq,chardev=vurdma'/>
</qemu:commandline>
```
