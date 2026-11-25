# XFS test images

Disk images used to exercise the read-only XFS driver. Every image was
formatted with `mkfs.xfs`, populated on a Linux host, verified with
`xfs_repair -n`, and mounted read-only to check its contents.

| File              | Size      | Format                                   | Entries | Git      |
| ----------------- | --------- | ---------------------------------------- | ------- | -------- |
| `xfs-16M.img`     | 16 MiB    | XFS v5, 1 AG, 4 KiB blocks, 512 B inodes | 236     | commit   |
| `xfs-32M.img`     | 32 MiB    | XFS v5, 2 AG, 4 KiB blocks, 512 B inodes | 236     | commit   |
| `xfs-300M.img`    | 300 MiB   | XFS v5, 4 AG, 4 KiB blocks, 512 B inodes | 2536    | ignored  |

16 MiB is the smallest valid XFS filesystem: the on-disk format requires an
allocation group of at least 16 MiB. `mkfs.xfs` 6.x additionally refuses
filesystems below 300 MiB, so the two small images are formatted with
xfsprogs 5.13 (Ubuntu 22.04) and the 300 MiB one with the current release.

The 300 MiB image is excluded from Git (`test-images/xfs-300M.img*` in
`.gitignore`); regenerate it on a Linux host with `mkfs.xfs` if needed.

## Contents

```
hello.txt                       "Hello from XFS!" (timestamp 2021-06-01)
README.txt                      this description, copied inside the image
empty.bin                       0-byte file
sparse.bin                      1 MiB of size, no block allocated
Case.txt / case.txt             case sensitivity
.hidden                         dotfile
special.fifo                    FIFO inode
data/exact-4096.bin             4096 bytes, exactly one block
data/exact-4097.bin             4097 bytes, one block plus one byte
data/random.bin                 64 KiB random (4 MiB on the 300 MiB image)
data/zeros.bin                  1 MiB of zeroes (8 MiB on the large image)
data/holes.bin                  128 KiB with three extents and holes
dirs/alpha/beta/gamma/file.txt  four levels of nesting
unicode/héllo-世界.txt          non-ASCII name
with space/nested dir/...       spaces in names
links/hardlink-hello.txt        hard link to hello.txt
links/symlink-hello.txt         relative symbolic link
links/dangling-symlink          symbolic link to a missing target
perms/private.txt               mode 0600
perms/exec.sh                   mode 0755
perms/setuid.bin                mode 4755
perms/setgid-dir                mode 2775
perms/sticky-dir                mode 1777
empty-dir                       empty directory, mode 0700
many/entry-0000..0199           many entries: directory out of shortform
many/entry-0000..2499           same, but forces node format (300 MiB image)
```

`hello.txt` also carries a `user.test` extended attribute when `python3` was
available while populating.

## Regenerating

The images can be rebuilt on any Linux host (or in a container) with:

```sh
truncate -s 32M xfs-32M.img
mkfs.xfs -f xfs-32M.img            # xfsprogs 5.13 for sizes below 300 MiB
sudo mount -o loop xfs-32M.img /mnt/xfs
sudo bash scripts/populate.sh /mnt/xfs small   # "large" for the 300 MiB image
sudo umount /mnt/xfs
xfs_repair -n -o force_geometry xfs-32M.img
sha256sum xfs-32M.img > xfs-32M.img.sha256
```

`scripts/populate.sh` is the script that produced the trees above.
