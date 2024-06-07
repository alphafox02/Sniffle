# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

from .ad_types import ManufacturerSpecificDataRecord

# Decoders for the Apple Continuity protocol
# References:
#   https://github.com/furiousMAC/continuity
#   https://github.com/netspooky/dissectors/blob/main/acble.lua

apple_message_types = {
    0x02: "iBeacon",
    0x03: "AirPrint",
    0x05: "AirDrop",
    0x06: "HomeKit",
    0x07: "Proximity Pairing",
    0x08: "Hey Siri",
    0x09: "AirPlay Target",
    0x0A: "AirPlay Source",
    0x0B: "MagicSwitch",
    0x0C: "Handoff",
    0x0D: "Tethering Target Presence",
    0x0E: "Tethering Source Presence",
    0x0F: "Nearby Action",
    0x10: "Nearby Info",
    0x12: "Find My"
}

class AppleMSDRecord(ManufacturerSpecificDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        self.msg_type = self.company_data[0]

    def str_msg_type(self):
        if self.msg_type in apple_message_types:
            return "%s (0x%02X)" % (apple_message_types[self.msg_type], self.msg_type)
        else:
            return "Unknown (0x%02X)" % self.msg_type

    def str_lines(self):
        lines = [self.str_type()]
        lines.append("Company: %s" % self.str_company())
        lines.append("Type: %s" % self.str_msg_type())
        lines.append("Data Length: %d" % len(self.company_data))
        lines.append("Data: %s" % repr(self.company_data))
        return lines

apple_message_classes = {
}

def decode_apple_msd(data_type: int, data: bytes):
    assert data_type == 0xFF
    if data[0] in apple_message_classes:
        return apple_message_classes[data[0]](data_type, data)
    else:
        return AppleMSDRecord(data_type, data)