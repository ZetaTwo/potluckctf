#!/bin/bash -e

if [ ! -f swgcc710-cross-6b-9916.tar.gz ]; then
    echo "Missing swgcc710-cross-6b-9916.tar.gz."
    # Original link: https://forum.developer.wxiat.com/forum.php?mod=viewthread&tid=339 (use Google Translate)
    # It is quite a hassle to download from Baidu Pan in script :(
    echo "You may download it from https://pan.baidu.com/s/1-oKKEdYJOFkrVArHCzkByw (password: 5u05)"
    exit 1
fi

sha256sum -c <<EOF
001b5e160163a404adb503689a8868499f5be82ab529fa3d309be9565832d2c4  swgcc710-cross-6b-9916.tar.gz
EOF