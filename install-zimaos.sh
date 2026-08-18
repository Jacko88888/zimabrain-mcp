#!/bin/sh
set -eu

REPOSITORY_URL="https://github.com/Jacko88888/zimabrain-mcp"
ARCHIVE_URL="${REPOSITORY_URL}/archive/refs/heads/main.tar.gz"
APP_DIR="${ZIMABRAIN_APP_DIR:-/DATA/AppData/zimabrain-mcp}"
ARCHIVE="/tmp/zimabrain-mcp-main.tar.gz"
STAGE="/tmp/zimabrain-mcp-install.$$"
OVERRIDE_FILE="${APP_DIR}/compose.detected-devices.yaml"

cleanup() {
  rm -f "$ARCHIVE"
  rm -rf "$STAGE"
}
trap cleanup EXIT INT TERM

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run this installer as root." >&2
  exit 1
fi

for command_name in docker lsblk awk sed tar; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "ERROR: required command is missing: $command_name" >&2
    exit 1
  fi
done

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: Docker Compose is not available." >&2
  exit 1
fi

for required_path in \
  /DATA \
  /media \
  /etc/os-release \
  /etc/hostname \
  /etc/machine-id \
  /etc/rauc/system.conf \
  /run/dbus/system_bus_socket \
  /run/log/journal \
  /var/log/journal; do
  if [ ! -e "$required_path" ]; then
    echo "ERROR: required ZimaOS evidence path is missing: $required_path" >&2
    exit 1
  fi
done

mkdir -p "$STAGE" "$APP_DIR" "$APP_DIR/data/brain"

if command -v curl >/dev/null 2>&1; then
  curl -fL "$ARCHIVE_URL" -o "$ARCHIVE"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$ARCHIVE" "$ARCHIVE_URL"
else
  echo "ERROR: curl or wget is required to download ZimaBrain MCP." >&2
  exit 1
fi

tar -xzf "$ARCHIVE" -C "$STAGE"
SOURCE_DIR="$STAGE/zimabrain-mcp-main"
if [ ! -f "$SOURCE_DIR/compose.portable.yaml" ]; then
  echo "ERROR: the downloaded release does not contain compose.portable.yaml." >&2
  exit 1
fi

cp -R "$SOURCE_DIR"/. "$APP_DIR"/

SATA_DEVICES=""
NVME_NAMESPACES=""
BTRFS_DEVICES=""
DEVICE_LINES=""

while read -r device_name device_type; do
  [ "$device_type" = "disk" ] || continue
  device_path="/dev/$device_name"
  [ -b "$device_path" ] || continue
  case "$device_name" in
    sd[a-z]*)
      SATA_DEVICES="${SATA_DEVICES}${SATA_DEVICES:+,}${device_path}"
      BTRFS_DEVICES="${BTRFS_DEVICES}${BTRFS_DEVICES:+,}${device_path}"
      DEVICE_LINES="${DEVICE_LINES}      - ${device_path}:${device_path}:r
"
      ;;
    nvme[0-9]*n[0-9]*)
      NVME_NAMESPACES="${NVME_NAMESPACES}${NVME_NAMESPACES:+,}${device_path}"
      BTRFS_DEVICES="${BTRFS_DEVICES}${BTRFS_DEVICES:+,}${device_path}"
      DEVICE_LINES="${DEVICE_LINES}      - ${device_path}:${device_path}:r
"
      ;;
  esac
done <<EOF
$(lsblk -dn -o NAME,TYPE)
EOF

NVME_CONTROLLERS=""
for controller_path in /sys/class/nvme/nvme[0-9]*; do
  [ -e "$controller_path" ] || continue
  controller="${controller_path##*/}"
  device_path="/dev/$controller"
  [ -e "$device_path" ] || continue
  NVME_CONTROLLERS="${NVME_CONTROLLERS}${NVME_CONTROLLERS:+,}${device_path}"
  DEVICE_LINES="${DEVICE_LINES}      - ${device_path}:${device_path}:r
"
done

if [ -z "$SATA_DEVICES$NVME_NAMESPACES" ]; then
  echo "ERROR: no supported SATA or NVMe disks were detected." >&2
  exit 1
fi

cat >"$OVERRIDE_FILE" <<EOF
services:
  storage-collector:
    environment:
      SATA_DEVICES: "${SATA_DEVICES}"
      NVME_CONTROLLERS: "${NVME_CONTROLLERS}"
      BTRFS_DEVICES: "${BTRFS_DEVICES}"
    devices:
${DEVICE_LINES}
EOF

cd "$APP_DIR"
docker compose -f compose.portable.yaml -f compose.detected-devices.yaml config >/dev/null
docker compose -f compose.portable.yaml -f compose.detected-devices.yaml build --pull
docker compose -f compose.portable.yaml -f compose.detected-devices.yaml up -d

echo "ZimaBrain MCP installation completed."
echo "Open: http://$(hostname -I 2>/dev/null | awk '{print $1}'):8621"
echo "Detected SATA devices: ${SATA_DEVICES:-none}"
echo "Detected NVMe controllers: ${NVME_CONTROLLERS:-none}"
echo "Detected NVMe namespaces: ${NVME_NAMESPACES:-none}"
