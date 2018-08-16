#!/usr/bin/env python3

# This utility extracts ADXCRYPT password hashes from IBM/Toshiba 4690 OS
# ADXCSOUF.DAT (more well-known, hence the name of the utility) and
# ADXEPW0F.DAT files.
#
# This software is Copyright (c) 2018, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Special thanks goes to Michael Dim for helping me with access to IBM/Toshiba
# 4690 v6.3 OS.
#
# Notes,
#
# 1. IBM/Toshiba 4690 v6.3 OS runs fine under VMware ESXi 6.7 (Select "Other
#    (64-bit)" as the Guest OS type), which itself is running under KVM using
#    nested virtualization.
#
# 2. Boot Linux on the 4690 system and use the following steps to extract the
#    ADXCSOUF.DAT and ADXEPW0F.DAT files. The ADXEPW0F.DAT file has the new
#    "Enhanced Security" SHA-1 hashes.
#
#    $ mkdir mnt/outer
#
#    $ mkdir mnt/inner
#
#    $ sudo mount /dev/sda3 mnt/outer  # change according to your setup
#
#    $ sudo mount -o loop mnt/outer/disk_c mnt/inner
#
#    # sudo cp mnt/inner/ADX_IDT1/ADXCSOUF.DAT ~
#    $ sudo cp mnt/inner/ADX_SDT1/ADXEPW0F.DAT ~

import re
import os
import sys
import json
import hashlib
import binascii

PY3 = sys.version_info[0] == 3


def process_file(filename):
    """
    Parser for ADXCSOUF.DAT files. Based on some trial-and-error.
    """
    data = open(filename, "rb").read()

    # find (username hash) pairs
    matches = re.findall(b'([ -~]+)\ (\d{8})', data)

    for items in matches:
        try:
            username = items[0]
            h = items[1]
        except:
            pass

        # dirty hack due to poor regex skills
        if b" " in username:
            continue

        if PY3:
            username = username.decode("ascii")
            h = h.decode("ascii")

        sys.stdout.write("%s:$adxcrypt$%s\n" % (username, h))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <ADXCSOUF.DAT file(s)>\n" % sys.argv[0])

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
