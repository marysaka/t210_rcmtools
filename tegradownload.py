#!/usr/bin/python3

import argparse
import sys
import rcm
import usb.core
import usb.util

parser = argparse.ArgumentParser()
parser.add_argument("image_path")
parser.add_argument("--keyindex", type=int, default=0)
parser.add_argument("--securedebugcontrol", type=int, default=0)

args = parser.parse_args()

key_data = bytes(16)

dev = usb.core.find(idVendor=0x0955, idProduct=0x7721)

# was it found?
if dev is None:
    raise ValueError("Device not found")

with open(args.image_path, "rb") as f:
    image_data = bytearray(f.read())

rcm_message = rcm.create_rcm21_download(
    image_data, 0x40010000, args.keyindex, args.securedebugcontrol
)
secure_offset = rcm.RCM21_RCM_MESSAGE_SECURE_START
secure_size = len(rcm_message) - secure_offset
hash_data = rcm.sbk_compute_hash(
    bytes(rcm_message), secure_offset, secure_size, key_data
)
rcm_message[
    rcm.RCM21_RCM_MESSAGE_CMAC_HASH_OFFSET : rcm.RCM21_RCM_MESSAGE_CMAC_HASH_OFFSET
    + 0x10
] = hash_data

# First we need to read the BR CID.
rcm.rcm_read_br_cid(dev)

message_id = rcm.get_rcm21_message_id(rcm_message[0 : rcm.RCM21_RCM_MESSAGE_SIZE])
result = rcm.rcm_transfer_message(dev, rcm_message)

if result == -1:
    print(f"USB error")
    sys.exit(1)
elif result != 0:
    print(f"RCM error {result}")
    sys.exit(1)
