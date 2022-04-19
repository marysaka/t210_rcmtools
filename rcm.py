import struct
from typing import Optional
from usb.core import USBTimeoutError
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

RCM_MESSAGE_MIN_SIZE = 0x400

rcm21_header_struct = (
    "<"
    # Length (insecure)
    + "I"
    # FSPK index (insecure)
    + "I"
    # FSPK wrap key
    + "32s"
    # RSA Key modulus
    + "256s"
    # CMAC Hash
    + "16s"
    # Signature (RSA PSS)
    + "256s"
    # Unknown (Seems it can be randomized?
    # On other payloads after bootrom this is named "Random AES"
    + "16s"
    # ECID
    + "16s"
    # Message ID
    + "I"
    # Length (secure)
    + "I"
    # Payload size
    + "I"
    # RCM version
    + "I"
    # Argument
    + "48s"
    # Secure Debug Control Flags
    + "I"
    # FSPK index (secure)
    + "I"
    # Padding (note this is non zero)
    + "8s"
)

RCM21_RCM_VERSION = 0x210001
RCM21_RCM_MESSAGE_SIZE = struct.calcsize(rcm21_header_struct)
RCM21_RCM_MESSAGE_SECURE_START = 0x238
RCM21_RCM_MESSAGE_CMAC_HASH_OFFSET = 0x128

RCM21_SYNC_ID = 1
RCM21_GET_BOOTROM_VERSION_ID = 5
RCM21_DOWNLOAD_ID = 4
RCM21_GET_RCM_VERSION_ID = 6
RCM21_GET_BD_VERSION_ID = 7


def decode_rcm21_message(rcm_message: bytearray):
    return struct.unpack(rcm21_header_struct, rcm_message)


def get_rcm21_message_id(rcm_message: bytearray):
    return decode_rcm21_message(rcm_message)[8]


def __compute_message_padding(message_size: int, payload_size: int) -> int:
    raw_size = message_size + payload_size

    padding_size = 0

    if raw_size < RCM_MESSAGE_MIN_SIZE:
        padding_size = RCM_MESSAGE_MIN_SIZE - raw_size
        raw_size += padding_size

    padding_size += 0x10 - ((raw_size - message_size) & 0xF)

    return padding_size


def __compute_message_size(message_size: int, payload_size: int) -> int:
    return (
        message_size
        + payload_size
        + __compute_message_padding(message_size, payload_size)
    )


def __set_padding(buffer: bytearray) -> bytearray:
    if len(buffer) != 0:
        buffer[0] = 0x80

        if len(buffer) > 1:
            for i in range(1, len(buffer)):
                buffer[i] = 0

    return buffer


def create_rcm21_message(
    message_id: int,
    argument: Optional[bytearray],
    payload: Optional[bytearray],
    fspk_index: int,
    secure_debug_control_flags: int,
) -> bytearray:
    if argument is None:
        argument = bytes(48)

    payload_len = 0

    if payload is not None:
        payload_len = len(payload)

    total_size = __compute_message_size(RCM21_RCM_MESSAGE_SIZE, payload_len)

    result = bytearray(total_size)

    # First initialize fields we are not going to fill with real data.
    fspk_wrap_key = bytearray(32)
    rsa_key_modulus = bytearray(256)
    cmac_hash = bytearray(16)
    signature = bytearray(256)
    random_aes = bytearray(16)
    ecid = bytearray(16)

    # Compute all padding
    padding = __set_padding(bytearray(8))
    result[RCM21_RCM_MESSAGE_SIZE + payload_len :] = __set_padding(
        result[RCM21_RCM_MESSAGE_SIZE + payload_len :]
    )

    # Encode message
    result[:RCM21_RCM_MESSAGE_SIZE] = struct.pack(
        rcm21_header_struct,
        total_size,
        fspk_index,
        fspk_wrap_key,
        rsa_key_modulus,
        cmac_hash,
        signature,
        random_aes,
        ecid,
        message_id,
        total_size,
        payload_len,
        RCM21_RCM_VERSION,
        argument,
        secure_debug_control_flags,
        fspk_index,
        padding,
    )

    # Finally write optional payload
    if payload is not None:
        result[RCM21_RCM_MESSAGE_SIZE : RCM21_RCM_MESSAGE_SIZE + len(payload)] = payload

    return result


def create_rcm21_sync(fspk_index: int, secure_debug_control_flags: int) -> bytearray:
    return create_rcm21_message(
        RCM21_SYNC_ID, None, None, fspk_index, secure_debug_control_flags
    )


def create_rcm21_get_rcm_version(
    fspk_index: int, secure_debug_control_flags: int
) -> bytearray:
    return create_rcm21_message(
        RCM21_GET_RCM_VERSION_ID, None, None, fspk_index, secure_debug_control_flags
    )


def create_rcm21_download(
    payload: bytearray,
    entrypoint: int,
    fspk_index: int,
    secure_debug_control_flags: int,
) -> bytearray:
    argument = bytearray(48)
    argument[:4] = struct.pack("I", entrypoint)

    return create_rcm21_message(
        RCM21_DOWNLOAD_ID, argument, payload, fspk_index, secure_debug_control_flags
    )


def create_rcm21_get_bootrom_version(
    fspk_index: int, secure_debug_control_flags: int
) -> bytearray:
    return create_rcm21_message(
        RCM21_GET_BOOTROM_VERSION_ID, None, None, fspk_index, secure_debug_control_flags
    )


def create_rcm21_get_bd_version(
    fspk_index: int, secure_debug_control_flags: int
) -> bytearray:
    return create_rcm21_message(
        RCM21_GET_BD_VERSION_ID, None, None, fspk_index, secure_debug_control_flags
    )


def rcm_read_br_cid(dev) -> Optional[bytes]:
    try:
        return dev.read(0x81, 0x10, 40)
    except USBTimeoutError:
        return None


def rcm_transfer_message(dev, message: bytes) -> int:
    length = len(message)
    packet_size = 0x1000

    try:
        # Write message
        while length:
            part_length = min(length, packet_size)
            part = message[:part_length]

            dev.write(0x01, part, 1000)

            message = message[part_length:]
            length -= part_length

        result_raw = dev.read(0x81, 4, 1000)

        return int.from_bytes(result_raw, "little")
    except:
        return -1


def get_default_download_address(chip_id: int) -> int:
    if chip_id == 0x21:
        return 0x40010000
    if chip_id == 0x13:
        return 0x4000F000

    raise Exception("TODO")


def sbk_compute_hash(data, offset, size, key_data):
    mac = cmac.CMAC(algorithms.AES(key_data))
    mac.update(data[offset : offset + size])
    result = mac.finalize()

    return result
