#!/usr/bin/sh
# cvmbuild dm-verity root activation — dracut module setup
#
# Activates dm-verity over /dev/vda1 (data) + /dev/vda2 (hash) at the
# pre-mount stage in the initrd, exposing /dev/mapper/root for the
# kernel `root=` flow to mount as the squashfs rootfs.
#
# This module is staged into /usr/lib/dracut/modules.d/90verity-cvm/
# by cvmbuild's stage_dracut_modules at base-image build time.

# Always include this module — it's the sole reason the initrd exists in
# a CVM image, and dracut's --add gives an explicit go-ahead anyway.
check() {
    return 0
}

depends() {
    # We deliberately do NOT depend on the dm or 70dm dracut module —
    # its check() requires the dmsetup binary and /dev/mapper/control,
    # neither of which is appropriate in our build environment (dmsetup
    # is removed by cvm.toml's security policy; control node is a
    # runtime kernel device). veritysetup talks to libdevmapper directly,
    # so no dependency is needed for our verity flow.
    return 0
}

installkernel() {
    # Drivers needed before /sysroot is mounted: dm-verity stack and the
    # virtio* family that QEMU exposes our root + data disks through.
    instmods dm-mod dm-verity dm-bufio squashfs \
             virtio_blk virtio_pci virtio_scsi virtio_net
}

install() {
    # veritysetup binary (from the cryptsetup-bin package)
    inst_multiple veritysetup

    # blkid probe trigger for dm-* devices — without this, wait-for-root
    # (libudev) blocks for 30s waiting for ID_FS_TYPE on /dev/mapper/root.
    inst_simple "$moddir/56-dm-blkid.rules" /etc/udev/rules.d/56-dm-blkid.rules

    # Run our verity-root hook just before /sysroot is mounted. Priority
    # 30 puts us after kernel-modules (10) and udev (20) but before any
    # filesystem-specific mount logic.
    inst_hook pre-mount 30 "$moddir/verity-root.sh"
}
