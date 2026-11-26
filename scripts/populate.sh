#!/usr/bin/env bash
# Populate a mounted XFS filesystem with a deterministic test tree.
#
# Usage: populate.sh <mountpoint> [small|large]
#
# The tree exercises what CrissCrossFS has to deal with: nested
# directories, short/long/unicode names, case sensitivity, hard and symbolic
# links, sparse and fragmented files, exact block-size boundaries, permission
# bits, xattrs, a FIFO, and directories big enough to leave shortform format.
set -euo pipefail

mnt=${1:?usage: populate.sh <mountpoint> [small|large]}
profile=${2:-small}

case "$profile" in
small)
    rand_size=65536        # 64 KiB
    zeros_size=1048576     # 1 MiB
    many_files=200         # -> block/leaf directory format
    ;;
large)
    rand_size=4194304      # 4 MiB
    zeros_size=8388608     # 8 MiB
    many_files=2500        # -> node directory format
    ;;
*)
    echo "unknown profile: $profile" >&2
    exit 2
    ;;
esac

mkdir -p "$mnt/data" \
         "$mnt/dirs/alpha/beta/gamma" \
         "$mnt/unicode" \
         "$mnt/with space/nested dir" \
         "$mnt/many" \
         "$mnt/perms" \
         "$mnt/links" \
         "$mnt/empty-dir"

printf 'Hello from XFS!\n' > "$mnt/hello.txt"

cat > "$mnt/README.txt" <<'EOF'
XFS test image
==============

This filesystem was formatted with mkfs.xfs and then populated by
scripts/populate.sh. It is meant to exercise CrissCrossFS:
directory formats, extents, sparse files, links, permissions and xattrs.
EOF

# Empty file (0 byte, no extent).
: > "$mnt/empty.bin"

# Files around the 4 KiB block boundary.
head -c 4096 /dev/zero > "$mnt/data/exact-4096.bin"
head -c 4097 /dev/zero > "$mnt/data/exact-4097.bin"

# Regular data files.
head -c "$rand_size" /dev/urandom > "$mnt/data/random.bin"
head -c "$zeros_size" /dev/zero > "$mnt/data/zeros.bin"

# Sparse file: 1 MiB of size, no block allocated.
truncate -s 1048576 "$mnt/sparse.bin"

# File with three extents separated by holes (head / middle / tail).
holes="$mnt/data/holes.bin"
truncate -s 131072 "$holes"
printf 'HEAD' | dd of="$holes" bs=1 seek=0 conv=notrunc status=none
printf 'MIDDLE' | dd of="$holes" bs=1 seek=65536 conv=notrunc status=none
printf 'TAIL' | dd of="$holes" bs=1 seek=131068 conv=notrunc status=none

# Nested directories and exotic names.
printf 'deep\n' > "$mnt/dirs/alpha/beta/gamma/file.txt"
printf 'unicode\n' > "$mnt/unicode/héllo-世界.txt"
printf 'spaces\n' > "$mnt/with space/nested dir/file with spaces.txt"
printf 'hidden\n' > "$mnt/.hidden"
printf 'case-sensitive A\n' > "$mnt/Case.txt"
printf 'case-sensitive b\n' > "$mnt/case.txt"

# Links.
ln "$mnt/hello.txt" "$mnt/links/hardlink-hello.txt"
ln -s ../hello.txt "$mnt/links/symlink-hello.txt"
ln -s /nonexistent/target "$mnt/links/dangling-symlink"

# Permission bits, setuid/setgid/sticky.
printf 'private\n' > "$mnt/perms/private.txt"
chmod 600 "$mnt/perms/private.txt"
printf '#!/bin/sh\necho hello\n' > "$mnt/perms/exec.sh"
chmod 755 "$mnt/perms/exec.sh"
printf 'setuid\n' > "$mnt/perms/setuid.bin"
chmod 4755 "$mnt/perms/setuid.bin"
mkdir -p "$mnt/perms/setgid-dir" "$mnt/perms/sticky-dir"
chmod 2775 "$mnt/perms/setgid-dir"
chmod 1777 "$mnt/perms/sticky-dir"
chmod 700 "$mnt/empty-dir"

# Fixed timestamps so the driver can be checked against known values.
touch -d '2021-06-01T12:34:56Z' "$mnt/hello.txt"
touch -d '2022-02-02T02:02:02Z' "$mnt/README.txt"

# Extended attribute (best effort: python3 may be absent).
if command -v python3 >/dev/null 2>&1; then
    python3 - "$mnt/hello.txt" <<'PY' || true
import os, sys
os.setxattr(sys.argv[1], b"user.test", b"xfs-image")
PY
fi

# FIFO: an XFS inode that is neither a file nor a directory.
if command -v mkfifo >/dev/null 2>&1; then
    mkfifo "$mnt/special.fifo"
fi

# Many entries: forces the directory out of shortform (block/leaf/node).
i=0
while [ "$i" -lt "$many_files" ]; do
    name=$(printf 'entry-%04d-abcdefghijklmnop.txt' "$i")
    : > "$mnt/many/$name"
    i=$((i + 1))
done

sync
echo "populated $mnt ($profile profile): $(find "$mnt" -mindepth 1 | wc -l) entries"
