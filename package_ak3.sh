#!/usr/bin/env bash
set -e

cp out/arch/arm64/boot/Image AnyKernel3/
rm -f AnyKernel3/dtbo.img

if [ -f "custom_dtb/dtb" ]; then
  cp custom_dtb/dtb AnyKernel3/dtb
else
  DTS="out/arch/arm64/boot/dts/vendor/qcom"
  cat "$DTS/lahaina-v2.1.dtb" "$DTS/lahaina-v2.dtb" "$DTS/lahaina.dtb" "$DTS/yupik.dtb" > AnyKernel3/dtb 2>/dev/null || \
  cat "$DTS"/*.dtb > AnyKernel3/dtb
fi

cat << 'AKEOF' > AnyKernel3/anykernel.sh
### AnyKernel3 Ramdisk Mod Script
## osm0sis @ xda-developers

### AnyKernel setup
properties() { '
kernel.string=NextGen-5.4.302-KSU-SUSFS by frenkymahn
do.devicecheck=1
do.modules=0
do.systemless=1
do.cleanup=1
do.cleanuponabort=0
device.name1=vili
device.name2=Vili
supported.versions=14 - 17
supported.patchlevels=
'; }

### AnyKernel install
block=/dev/block/bootdevice/by-name/boot;
is_slot_device=1;
ramdisk_compression=auto;
patch_vbmeta_flag=auto;

. tools/ak3-core.sh;

# boot install - replace kernel in boot partition
dump_boot;
write_boot;

## vendor_boot - flash Android 16/17 DTB + keep vendor ramdisk & stock DTBO intact
block=/dev/block/bootdevice/by-name/vendor_boot;
is_slot_device=1;
ramdisk_compression=auto;
patch_vbmeta_flag=auto;

reset_ak;
split_boot;
flash_boot;
AKEOF

cd AnyKernel3
rm -rf .git
zip -r9 ../NextGen-5.4.302-KSU-SUSFS-Vili.zip * -x .git README.md *placeholder
