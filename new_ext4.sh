#!/bin/bash

set -x

dd if=/dev/zero of=img.ext4 bs=1M count=256
mkfs.ext4 -q -b 4096 -o Lites -O none img.ext4

mkdir -p rootfs
sudo mount img.ext4 rootfs
cd rootfs
sudo mkdir -p 1/2/3/4/5
cd ..
tree -L 5 rootfs
sudo umount rootfs
