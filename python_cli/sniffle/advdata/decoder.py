# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

from struct import unpack
from .ad_types import *
from .msd_apple import AppleMSDRecord
from .msd_microsoft import MicrosoftMSDRecord
from .msd_remoteid import RemoteIDRecord  # Import RemoteIDRecord class

company_msd_decoders = {
    0x0006: MicrosoftMSDRecord,
    0x004C: AppleMSDRecord
}

def decode_msd(data_type: int, data: bytes):
    company, = unpack("<H", data[:2])
    if company in company_msd_decoders:
        return company_msd_decoders[company](data_type, data)
    else:
        return ManufacturerSpecificDataRecord(data_type, data)

def decode_remote_id(data_type: int, data: bytes):
    # Implement your Remote ID decoding logic here
    service_data = data[2:]  # Skip initial bytes if needed based on your structure

    message_counter = service_data[0]  # Adjust as per your packet structure
    messages = []

    # Process the message pack
    message_size = service_data[2]
    message_quantity = service_data[3]
    offset = 4

    for _ in range(message_quantity):
        message_type = (service_data[offset] >> 4) & 0x0F
        message_version = service_data[offset] & 0x0F
        message_data_length = service_data[offset + 1]
        message_data = service_data[offset + 2: offset + 2 + message_data_length]

        # Append parsed message to messages list
        messages.append({
            "type": message_type,
            "version": message_version,
            "data": message_data
        })

        # Move offset to the next message
        offset += 2 + message_data_length

    return RemoteIDRecord(data_type, data, message_counter, messages)

# Dictionary mapping advertisement types to their respective record classes or decoding functions
ad_type_classes = {
    0x01: FlagsRecord,
    0x02: ServiceList16Record,
    0x03: ServiceList16Record,
    0x04: ServiceList32Record,
    0x05: ServiceList32Record,
    0x06: ServiceList128Record,
    0x07: ServiceList128Record,
    0x08: ShortenedLocalNameRecord,
    0x09: CompleteLocalNameRecord,
    0x0A: TXPowerLevelRecord,
    0x16: ServiceData16Record,
    0x20: ServiceData32Record,
    0x21: ServiceData128Record,
    0xFF: decode_remote_id,  # Use decode_remote_id for ad type 0xFF
}

def record_from_type_data(data_type: int, data: bytes):
    if data_type in ad_type_classes:
        try:
            return ad_type_classes[data_type](data_type, data)
        except Exception as e:
            print(f"Exception decoding ad type {data_type}: {e}")
            return AdvDataRecord(data_type, data, malformed=True)
    else:
        return AdvDataRecord(data_type, data)

def decode_adv_data(data):
    records = []
    i = 0

    while i < len(data):
        try:
            l = data[i]
            t = data[i+1]
            d = data[i+2:i+1+l]
            records.append(record_from_type_data(t, d))
            i += 1+l
        except Exception as e:
            print(f"Exception decoding advertising data: {e}")
            break

    return records
