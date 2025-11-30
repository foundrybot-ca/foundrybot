#!/usr/bin/env bash
# 06_rebuild_iso.sh - rebuild Debian 13 ZFS live ISO and add auto-install entries

set -euo pipefail

ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$ZFS_LIVE_ROOT/utils.sh"

zfs_setup_err_trap "$(basename "$0")"

main() {
  info "=== 06_rebuild_iso: Rebuilding ZFS live ISO ==="

  require_cmd xorriso sed

  die_if_missing "$ZFS_ISO_WORK_DIR" "ISO work directory"
  die_if_missing "$ZFS_SQUASHFS_IMAGE" "rebuilt SquashFS image"

  # ---------------------------------------------------------------------------
  # 1) Patch BIOS isolinux config for Auto ZFS Install entry
  # ---------------------------------------------------------------------------
  local isolinux_cfg="$ZFS_ISO_WORK_DIR/isolinux/live.cfg"
  local kernel_params="boot=live components quiet splash ${ZFS_KERNEL_FLAG_ENABLE} ${ZFS_KERNEL_FLAG_DISK_PARAM}=${ZFS_ROOT_DISK}"

  if [[ "${ZFS_ADD_SERIAL_CONSOLE:-false}" == "true" ]]; then
    kernel_params+=" console=ttyS0,115200n8"
  fi

  if [[ -f "$isolinux_cfg" ]]; then
    info "Patching isolinux config: $isolinux_cfg"
    cat >>"$isolinux_cfg" <<EOF

label auto-zfs
    menu label ^${ZFS_BOOT_MENU_LABEL}
    linux /live/vmlinuz
    initrd /live/initrd.img
    append ${kernel_params}
EOF
  else
    warn "isolinux/live.cfg not found at $isolinux_cfg; BIOS menu will not get Auto ZFS entry."
  fi

  # ---------------------------------------------------------------------------
  # 2) Patch UEFI GRUB config for Auto ZFS Install entry
  # ---------------------------------------------------------------------------
  local grub_cfg="$ZFS_ISO_WORK_DIR/boot/grub/grub.cfg"
  if [[ -f "$grub_cfg" ]]; then
    info "Patching GRUB config: $grub_cfg"
    cat >>"$grub_cfg" <<EOF

menuentry "${ZFS_BOOT_MENU_LABEL}" {
    linux   /live/vmlinuz ${kernel_params}
    initrd  /live/initrd.img
}
EOF
  else
    warn "GRUB config not found at $grub_cfg; UEFI menu will not get Auto ZFS entry."
  fi

  # ---------------------------------------------------------------------------
  # 3) Rebuild ISO with xorriso -as mkisofs
  # ---------------------------------------------------------------------------
  mkdir -p "$ZFS_OUTPUT_DIR"
  local out_iso="$ZFS_OUTPUT_ISO_PATH"

  info "Building ISO image: $out_iso"

  local mbr_opt=()
  local mbr_path="$ZFS_ISO_WORK_DIR/isolinux/isohdpfx.bin"
  if [[ -f "$mbr_path" ]]; then
    info "Using isohybrid MBR: $mbr_path"
    mbr_opt=(-isohybrid-mbr "isolinux/isohdpfx.bin")
  else
    warn "isohdpfx.bin not found under isolinux/; building ISO without explicit isohybrid MBR."
  fi

  (
    cd "$ZFS_ISO_WORK_DIR"
    run xorriso -as mkisofs \
      -r -V "DEBIAN_13_ZFS_LIVE" \
      -o "$out_iso" \
      -J -joliet-long -cache-inodes \
      "${mbr_opt[@]}" \
      -c isolinux/boot.cat \
      -b isolinux/isolinux.bin \
      -no-emul-boot -boot-load-size 4 -boot-info-table \
      -eltorito-alt-boot \
      -e boot/grub/efi.img \
      -no-emul-boot \
      .
  )

  if [[ ! -f "$out_iso" ]]; then
    die "ISO build failed: $out_iso not created"
  fi

  info "06_rebuild_iso: ISO created at $out_iso"
}

main "$@"

