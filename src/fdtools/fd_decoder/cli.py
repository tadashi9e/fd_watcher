# -*- coding: utf-8; mode:python -*-
import errno
import sys
import json
import socket
import traceback
try:
    from typing import Any, Callable, Dict, Tuple
except:
    pass

# /usr/include/linux/bpf.h
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
    "0D": "TCP_BOUND_INACTIVE",
}

# /usr/include/linux/eventpoll.h
EPOLL_EVENT_MASK = {
    0x001: "IN",
    0x002: "PRI",
    0x004: "OUT",
    0x008: "ERR",
    0x010: "HUP",
    0x020: "INVAL",
    0x040: "RDNORM",
    0x080: "RDBAND",
    0x100: "WRNORM",
    0x200: "WRBAND",
    0x400: "MSG",
    0x800: "RDHUP",
    0x08000000: "URING_WAKE",
    0x10000000: "EPOLLEXCLUSIVE",
}
SORTED_EPOLL_EVENT_MASK = sorted(EPOLL_EVENT_MASK, reverse = True)

# /usr/include/asm-generic/fcntl.h
O_ACCMODE = 0x00000003
O_RDONLY  = 0x00000000
O_WRONLY  = 0x00000001
O_RDWR    = 0x00000002
O_FLAGS = {
    0x00000100: "CREAT",
    0x00000200: "EXCL",
    0x00000400: "NOCTTY",
    0x00001000: "TRUNC",
    0x00002000: "APPEND",
    0x00004000: "NONBLOCK",
    0x00010000: "DSYNC",
    0x00020000: "FASYNC",
    0x00040000: "DIRECT",
    0x00100000: "LARGEFILE",
    0x00200000: "DIRECTORY",
    0x00400000: "NOFOLLOW",
    0x01000000: "NOATIME",
    0x02000000: "CLOEXEC",
}
SORTED_O_FLAGS = sorted(O_FLAGS, reverse = True)

def decode_epoll_events(hex_events : str) -> str:
    try:
        events = int(hex_events, 16)
    except ValueError:
        return hex_events
    names = []
    for b in SORTED_EPOLL_EVENT_MASK:
        if events & b:
            names.append(EPOLL_EVENT_MASK[b])
    return '|'.join(names) if names else '0'

def decode_flags(hex_flags : str) -> str:
    try:
        flags = int(hex_flags, 16)
    except ValueError:
        return hex_flags
    accmode = flags & O_ACCMODE
    names = ['RDONLY' if accmode == O_RDONLY else
             'WRONLY' if accmode == O_WRONLY else
             'RDWR' if accmode == O_RDWR else
             hex(accmode)]
    for b in SORTED_O_FLAGS:
        if flags & b:
            names.append(O_FLAGS[b])
    known_mask = O_ACCMODE
    for b in O_FLAGS:
        known_mask |= b
    unknown_bits = flags & ~known_mask
    if unknown_bits:
        names.append(hex(unknown_bits))
    return '|'.join(names)
def decode_tcp_st(st : str) -> str:
    return TCP_STATES[st] if st in TCP_STATES else st
def decode_unix_st(st : str) -> str:
    return ("UNCONNECTED" if st == "01" else
            "CONNECTING" if st == "02" else
            "CONNECTED" if st == "03" else
            "DISCONNECTING" if st == "04" else
            st)
def decode_ip4_port(s : str) -> str:
    try:
        ip_hex, port_hex = s.split(":")
        ip = socket.inet_ntop(socket.AF_INET, bytes.fromhex(ip_hex)[::-1])
    except (ValueError, OSError):
        return s
    port = int(port_hex, 16)
    return f"{ip}:{port}"
def decode_ip6_port(s : str) -> str:
    try:
        ip_hex, port_hex = s.split(":")
    except ValueError:
        return s
    raw = bytes.fromhex(ip_hex)
    # little-endian
    chunks = [raw[i:i+4][::-1] for i in range(0, 16, 4)]
    try:
        ip = socket.inet_ntop(socket.AF_INET6, b''.join(chunks))
    except (ValueError, OSError):
        return s
    port = int(port_hex, 16)
    return f"{ip}:{port}"
# ----------------------------------------------------------------------
def dict_decoder(target : Dict[str, Any],
                 rules : Dict[str, Callable[[Any], Any]]) -> Dict[str, Any]:
    decoded = {
        key: rules[key](value) if key in rules else value
        for key, value in target.items()}
    return decoded
def decode_tfds(tfds : Dict[str, Any]) -> Dict[str, Any]:
    return {
        tfd: dict_decoder(entry, {'events': decode_epoll_events})
        for tfd, entry in tfds.items()
    }
def decode_info(info : Dict[str, Any]) -> Dict[str, Any]:
    decoded = dict_decoder(
        info,
        {'flags': decode_flags,
         'tfds': decode_tfds})
    itype = info.get('type', '')
    if itype in ('UDP', 'TCP'):
        if 'local' in info:
            decoded['local'] = decode_ip4_port(info['local'])
        if 'remote' in info:
            decoded['remote'] = decode_ip4_port(info['remote'])
        if 'st' in info:
            decoded['st'] = decode_tcp_st(info['st'])
    elif itype in ('UDP6', 'TCP6'):
        if 'local' in info:
            decoded['local'] = decode_ip6_port(info['local'])
        if 'remote' in info:
            decoded['remote'] = decode_ip6_port(info['remote'])
        if 'st' in info:
            decoded['st'] = decode_tcp_st(info['st'])
    elif itype == 'UNIX':
        if 'st' in info:
            decoded['st'] = decode_unix_st(info['st'])
    return decoded
def decode(event : Dict[str, Any]) -> Dict[str, Any]:
    return dict_decoder(
        event,
        {'new': decode_info,
         'old': decode_info})
# ----------------------------------------------------------------------
def main() -> None:
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                print(json.dumps(decode(event), separators = (',', ':')),
                      flush = True)
            except json.JSONDecodeError:
                print(line, file = sys.stderr)
                traceback.print_exc(file = sys.stderr)
    except KeyboardInterrupt:
        pass
    except socket.error as e:
        if e.errno != errno.EPIPE:
            raise
