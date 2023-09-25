import argparse
import base64
import sys
from functools import partial
import requests

COMMANDS = {
    "WHOISHERE": 0x01,
    "IAMHERE": 0x02,
    "GETSTATUS": 0x03,
    "STATUS": 0x04,
    "SETSTATUS": 0x05,
    "TICK": 0x06,
}

DEVICES = {
    "SmartHub": 0x01,
    "EnvSensor": 0x02,
    "Switch": 0x03,
    "Lamp": 0x04,
    "Socket": 0x05,
    "Clock": 0x06,
}


class HubException(Exception):
    pass


class InvalidFormatException(Exception):
    pass


def gen_crc8():
    generator = 0x1D
    table = [0] * 256
    for dividend in range(256):
        curr_byte = dividend
        for _ in range(8):
            if (curr_byte & 0x80) != 0:
                curr_byte = curr_byte << 1
                curr_byte = curr_byte ^ generator
            else:
                curr_byte = curr_byte << 1

            curr_byte = curr_byte & 0xFF
        table[dividend] = curr_byte
    return table


CRC8_TABLE = gen_crc8()


def encode_byte(data: int) -> bytes:
    return data.to_bytes(length=1, byteorder="big")


def crc8(data: bytes) -> bytes:
    crc = 0
    for byte in data:
        crc = CRC8_TABLE[crc ^ byte]
    return encode_byte(crc)


def encode_varuint(data: int) -> bytes:
    seven_bits = 0b1111111
    high_bit = seven_bits + 1

    result_ints = []
    while data != 0:
        cur = data & seven_bits
        result_ints.append(cur | high_bit)
        data = data >> 7

    if not result_ints:
        return b"\x00"

    result_ints[-1] = result_ints[-1] & seven_bits
    return bytes(result_ints)


def encode_str(s: str) -> bytes:
    encoded = s.encode(encoding="ascii")
    return encode_byte(len(encoded)) + encoded


def encode_list(data: list[bytes]) -> bytes:
    return encode_byte(len(data)) + b"".join(data)


def encode_b64(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def build_packet(payload: bytes) -> bytes:
    return encode_byte(len(payload)) + payload + crc8(payload)


def decode_b64(data: bytes) -> bytes:
    clean = []
    for b in data:
        c = chr(b)
        if c.isspace():
            continue

        if not (c.isalnum() or c == "-" or c == "_"):
            raise InvalidFormatException("invalid characters in base64")

        clean.append(b)
    return base64.urlsafe_b64decode(bytes(clean) + b"===")


def parse_varuint(data: bytes) -> tuple[int, int]:
    seven_bits = 0b1111111
    high_bit = seven_bits + 1
    result = 0
    i = 0
    while True:
        b = data[i]
        result |= (b & seven_bits) << (i * 7)
        if not b & high_bit:
            break
        i += 1
    return result, i + 1


def parse_str(data: bytes) -> tuple[str, int]:
    size = data[0]
    return data[1: size + 1].decode(encoding="ascii"), size + 1


def parse_byte(data: bytes) -> tuple[int, int]:
    return data[0], 1


def parse_arr(type_parser, data: bytes) -> tuple[list, int]:
    offset = 1
    size = data[0]
    result = []
    for _ in range(size):
        r, delta = type_parser(data[offset:])
        result.append(r)
        offset += delta

    return result, offset + 1


def parse_sequence(type_parsers: list, data: bytes) -> tuple[list, int]:
    offset = 0
    result = []
    for p in type_parsers:
        r, delta = p(data[offset:])
        result.append(r)
        offset += delta

    return result, offset


def parse_sequence_terminal(type_parsers: list, data: bytes) -> list:
    offset = 0
    result = []
    for p in type_parsers:
        r, delta = p(data[offset:])
        result.append(r)
        offset += delta

    if offset < len(data):
        raise InvalidFormatException("did not reach EOF when parsing sequence")

    return result


def parse_trigger(data: bytes) -> tuple[dict, int]:
    val, offset = parse_sequence([parse_byte, parse_varuint, parse_str], data)
    return dict(zip(["op", "value", "name"], val)), offset


def parse_dev_props(dev_type: int, data: bytes) -> tuple[list | dict, int]:
    try:
        if dev_type == DEVICES["EnvSensor"]:
            seq, offset = parse_sequence([parse_byte, partial(parse_arr, parse_trigger)], data)
            support_byte, triggers = seq
            supported_sensors = []
            for mask, sensor in [(0x1, "temperature"),
                                 (0x2, "humidity"),
                                 (0x4, "light"),
                                 (0x8, "pollution")]:
                if support_byte & mask:
                    supported_sensors.append(sensor)

            triggers_decoded = []
            for trigger in triggers:
                op, value, name = trigger["op"], trigger["value"], trigger["name"]
                on = bool(op & 0b1)
                greater = bool(op & 0b10)
                typ = ["temperature", "humidity", "light", "pollution"][(op >> 2) & 0b11]
                triggers_decoded.append({
                    "on": on,
                    "greater": greater,
                    "type": typ,
                    "value": value,
                    "name": name,
                })

            return {
                "supported_sensors": supported_sensors,
                "triggers": triggers_decoded,
            }, offset
        elif dev_type == DEVICES["Switch"]:
            return parse_arr(parse_str, data)
        else:
            return {}, 0
    except IndexError:
        raise InvalidFormatException('got EOF when parsing dev_props')


def parse_cmd_body(cmd: int, dev_type: int, data: bytes) -> dict:
    try:
        if cmd in [COMMANDS["IAMHERE"], COMMANDS["WHOISHERE"]]:
            dev_name, dev_props = parse_sequence_terminal([parse_str, partial(parse_dev_props, dev_type)], data)
            return {
                "dev_name": dev_name,
                "dev_props": dev_props,
            }
        elif cmd == COMMANDS["TICK"]:
            ts, = parse_sequence_terminal([parse_varuint], data)
            return {"timestamp": ts}
        elif cmd == COMMANDS["STATUS"]:
            if dev_type == DEVICES["EnvSensor"]:
                return {"values": parse_sequence_terminal([partial(parse_arr, parse_varuint)], data)[0]}
            elif dev_type in [DEVICES["Socket"], DEVICES["Lamp"], DEVICES["Switch"]]:
                value, = parse_sequence_terminal([parse_byte], data)
                return {"value": value}

            return {}
        elif cmd in [COMMANDS["GETSTATUS"], COMMANDS["SETSTATUS"]]:
            return {}

        raise InvalidFormatException("unexpected cmd when parsing cmd_body")
    except IndexError:
        raise InvalidFormatException("unexpected EOF when parsing cmd_body")


def parse_payload(data: bytes) -> dict:
    try:
        offset = 0
        src, delta = parse_varuint(data)
        offset += delta
        dst, delta = parse_varuint(data[offset:])
        offset += delta

        if not 0x0000 <= src <= 0x3FFF:
            raise InvalidFormatException("src is too big")
        if not 0x0000 <= dst <= 0x3FFF:
            raise InvalidFormatException("dst is too big")

        serial, delta = parse_varuint(data[offset:])
        offset += delta
        dev_type = data[offset]
        cmd = data[offset + 1]
        data = data[offset + 2:]

        if not 0x2 <= dev_type <= 0x6:  # 0x1 is SmartHub
            raise InvalidFormatException("unexpected device type in payload")
        if not 0x1 <= cmd <= 0x6:
            raise InvalidFormatException("unexpected command in payload")

        return {
            "src": src,
            "dst": dst,
            "serial": serial,
            "dev_type": dev_type,
            "cmd": cmd,
            "cmd_body": parse_cmd_body(cmd, dev_type, data),
        }

    except IndexError:
        raise InvalidFormatException("payload has ended unexpectedly")


def decode_response(data: bytes) -> list[dict]:
    data = decode_b64(data)
    result = []

    if len(data) == 0:
        return []

    start = 0
    try:
        while True:
            size = data[start]
            payload = data[start + 1: start + 1 + size]
            checksum = data[start + 1 + size]
            if crc8(payload) != encode_byte(checksum):
                raise InvalidFormatException("crc8 check failure")
            result.append(parse_payload(payload))

            start = start + 1 + size + 1
            if start == len(data):
                break
    except IndexError:
        raise InvalidFormatException("list of packets has ended unexpectedly")

    if start != len(data):
        raise InvalidFormatException(
            "list of packets has unexpected bytes instead of EOF"
        )

    return result


class Hub:
    _dev_type = 1

    def __init__(self, address, src, name="SMARTHUB"):
        self._addr = address
        self._src = src
        self._serial = 1
        self._timestamp = -1
        self._devices = {}
        self._device_addrs = {}
        self._name_encoded = encode_str(name)

        self._requests = {}

        self._send_i_am_here = False
        self._new_get_requests = set()
        self._new_set_requests = set()

        try:
            # send initial WHOISHERE
            try:
                code, response = self._post(
                    build_packet(
                        self._build_payload(0x3FFF, COMMANDS["WHOISHERE"], self._name_encoded)
                    )
                )

                if code not in [200, 204]:
                    raise HubException("HTTP error code")

                # print(response)
            except InvalidFormatException:
                return

            self._update_timer(response)
            self._requests[self._timestamp] = [{"type": "WHOISHERE"}]

            assert self._timestamp != -1
            for packet in response:
                if packet["cmd"] == COMMANDS["IAMHERE"]:
                    self._add_device(packet)

        except requests.exceptions.RequestException as e:
            raise HubException(e)

    def serve(self):
        try:
            while True:
                try:
                    code, response = self._post(self._gen_request())
                    if code not in [200, 204]:
                        raise HubException("HTTP error code")

                except InvalidFormatException:
                    continue

                self._update_timer(response)

                timed_out = [ts for ts in self._requests if self._timestamp > ts + 300]
                for ts in timed_out:
                    for req in self._requests[ts]:
                        if req["type"] in ["SETSTATUS", "GETSTATUS"] and "done" not in req:
                            addr = req["addr"]
                            name = self._device_addrs[addr]["name"]
                            del self._devices[name], self._device_addrs[addr]
                    del self._requests[ts]

                self._handle_response(response)
                # time.sleep(1)

                if code == 204:
                    return
        except requests.exceptions.RequestException as e:
            raise HubException(e)

    def _build_payload(self, dst: int, cmd: int, cmd_body: bytes, dev_type: int | None = None):
        if dev_type is None:
            dev_type = self._dev_type
        return (
                encode_varuint(self._src)
                + encode_varuint(dst)
                + encode_varuint(self._serial)
                + encode_byte(dev_type)
                + encode_byte(cmd)
                + cmd_body
        )

    def _post(self, payload: bytes | None = None) -> tuple[int, list[dict]]:
        body = encode_b64(payload) if payload is not None else b""
        response = requests.post(self._addr, data=body, timeout=1)
        code = response.status_code
        data = decode_response(response.content)
        self._serial += 1
        return code, data

    def _update_timer(self, responses: list[dict]):
        for packet in responses:
            if packet["cmd"] == COMMANDS["TICK"]:
                if packet["dev_type"] != 0x06:
                    continue
                self._timestamp = packet["cmd_body"]["timestamp"]

    def _handle_response(self, responses: list[dict]):
        has_who_is_here = self._check_req(lambda req: req["type"] == "WHOISHERE")
        for packet in responses:
            src = packet["src"]

            if packet["cmd"] == COMMANDS["IAMHERE"] and has_who_is_here:
                self._add_device(packet)
            elif packet["cmd"] == COMMANDS["WHOISHERE"]:
                self._send_i_am_here = True
                self._add_device(packet)

            if src not in self._device_addrs and src != 0x3FFF:
                continue

            if packet["cmd"] == COMMANDS["STATUS"]:
                for requests in self._requests.values():
                    for req in requests:
                        if req["type"] in ["GETSTATUS", "SETSTATUS"] and req["addr"] == packet["src"]:
                            req["done"] = True

                if packet["dev_type"] == DEVICES["Switch"]:
                    for name in self._device_addrs[src]["dev_props"]:
                        self._new_set_requests.add((name, encode_byte(packet["cmd_body"]["value"])))
                elif packet["dev_type"] == DEVICES["EnvSensor"]:
                    dev_props = self._device_addrs[src]["dev_props"]
                    sensors = dev_props["supported_sensors"]
                    values = packet["cmd_body"]["values"]
                    for trigger in dev_props["triggers"]:
                        on = trigger["on"]
                        greater = trigger["greater"]
                        typ = trigger["type"]
                        value = values[sensors.index(typ)]
                        threshold = trigger["value"]
                        over_threshold = value >= threshold if greater else value <= threshold
                        result = int(over_threshold if on else not over_threshold)
                        self._new_set_requests.add((trigger["name"], result))

    def _check_req(self, predicate) -> bool:
        for requests in self._requests.values():
            for req in requests:
                if predicate(req):
                    return True
        return False

    def _gen_request(self) -> bytes:
        if self._timestamp not in self._requests:
            self._requests[self._timestamp] = []

        get_status_req = b"".join(build_packet(self._build_payload(
            self._devices[name]["addr"],
            COMMANDS["GETSTATUS"],
            b"",
            dev_type=self._devices[name]["dev_type"]
        )) for name in self._new_get_requests
                                  if name in self._devices and
                                  self._devices[name]["dev_type"] not in [DEVICES["Clock"],
                                                                          DEVICES["SmartHub"]])
        self._requests[self._timestamp] += [{"type": "GETSTATUS",
                                             "addr": self._devices[name]["addr"]}
                                            for name in self._new_get_requests
                                            if name in self._devices and
                                            self._devices[name]["dev_type"] not in [DEVICES["Clock"],
                                                                                    DEVICES["SmartHub"]]]
        self._new_get_requests.clear()

        i_am_here_req = build_packet(
            self._build_payload(0x3FFF, COMMANDS["IAMHERE"], self._name_encoded)
        ) if self._send_i_am_here else b""

        set_status_req = b"".join(build_packet(self._build_payload(
            self._devices[name]["addr"],
            COMMANDS["SETSTATUS"],
            value,
            dev_type=self._devices[name]["dev_type"]
        )) for name, value in self._new_set_requests
                                  if name in self._devices)
        self._requests[self._timestamp] += [{"type": "SETSTATUS",
                                             "addr": self._devices[name]["addr"]}
                                            for name, _ in self._new_set_requests
                                            if name in self._devices]
        self._new_set_requests.clear()

        return get_status_req + set_status_req + i_am_here_req

    def _add_device(self, packet: dict):
        self._devices[packet["cmd_body"]["dev_name"]] = self._device_addrs[packet["src"]] = {
            "dev_type": packet["dev_type"],
            "addr": packet["src"],
            "name": packet["cmd_body"]["dev_name"],
            "dev_props": packet["cmd_body"]["dev_props"],
        }
        self._new_get_requests.add(packet["cmd_body"]["dev_name"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Smart device hub")
    parser.add_argument("server_address")
    parser.add_argument("hub_address")

    args = parser.parse_args()
    server_address = args.server_address
    hub_address = int(args.hub_address, 16)

    try:
        if hub_address <= 0x0000 or hub_address >= 0x3FFF:
            raise HubException("invalid hub address")
        hub = Hub(server_address, hub_address)
        hub.serve()
    except HubException as e:
        print(e, file=sys.stderr)
        sys.exit(99)
