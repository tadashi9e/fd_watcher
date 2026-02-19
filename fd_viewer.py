#!/usr/bin/env python3
# -*- coding: utf-8; mode:python -*-
import sys
import json
import socket
import traceback
try:
    from typing import Any, Dict
except:
    pass

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"

COLOR_MAP = {
    '+': GREEN,
    '-': RED,
    '>': YELLOW,
}

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

def decode_epoll_events(hex_events : str) -> str:
    try:
        events = int(hex_events, 16)
        names = []
        for b in sorted(EPOLL_EVENT_MASK):
            if events & b:
                names.append(EPOLL_EVENT_MASK[b])
        return '|'.join(names)
    except:
        return hex_events

def decode_flags(hex_flags : str) -> str:
    try:
        flags = int(hex_flags, 16)
        accmode = flags & O_ACCMODE
        names = ['RDONLY' if accmode == O_RDONLY else
                 'WRONLY' if accmode == O_WRONLY else
                 'RDWR' if accmode == O_RDWR else
                 hex(accmode)]
        for b in sorted(O_FLAGS):
            if flags & b:
                names.append(O_FLAGS[b])
        return '|'.join(names)
    except:
        return hex_flags

def hex_ip_port(s : str) -> str:
    ip_hex, port_hex = s.split(":")
    ip = socket.inet_ntop(socket.AF_INET, bytes.fromhex(ip_hex)[::-1])
    port = int(port_hex, 16)
    return f"{ip}:{port}"
def hex_ip6_port(s : str) -> str:
    ip_hex, port_hex = s.split(":")
    raw = bytes.fromhex(ip_hex)
    chunks = [raw[i:i+4][::-1] for i in range(0, 16, 4)]
    ip = socket.inet_ntop(socket.AF_INET6, b''.join(chunks))
    port = int(port_hex, 16)
    return f"{ip}:{port}"
def cprint(update_type : str, s : str) -> None:
    if sys.stdout.isatty() and update_type in COLOR_MAP:
        print(COLOR_MAP[update_type] + s + RESET)
        return
    print(s)
def cdisplay(update_type : str,
             timestamp : str, fd : str, itype : str,
             info: Dict[str, Any]) -> None:
    inode = info['inode'] if 'inode' in info else ''
    flags = decode_flags(info['flags']) if 'flags' in info else ''
    target = info['target'] if 'target' in info else ''
    cprint(update_type,
           f'{timestamp} {fd:>5} {update_type}{itype:<6} {inode:>10} {flags:<25} {target}')
def display_unknown(timestamp : str, update_type : str, fd : str,
                    info: Dict[str, Any]) -> None:
    cdisplay(update_type, timestamp, fd, '?', info)
def display_socket(timestamp : str, update_type : str, fd : str,
                   info: Dict[str, Any]) -> None:
    cdisplay(update_type, timestamp, fd, 'SOCKET', info)
def display_net(timestamp : str, update_type : str,
                fd : str, info : Dict[str, str]) -> None:
    header = f'{timestamp} {fd:>5}'
    inode = info['inode'] if 'inode' in info else ''
    itype = info['type'] if 'type' in info else ''
    l_addr_port = hex_ip_port(info['local'])
    r_addr_port = hex_ip_port(info['remote'])
    hex_st = info['st']
    st = TCP_STATES[hex_st] if hex_st in TCP_STATES else hex_st
    cprint(
        update_type,
        header +
        f' {update_type}{itype:<6} {inode:>10} {l_addr_port} {r_addr_port} {st}')

def display_net6(timestamp : str, update_type : str,
                 fd : str, info : Dict[str, str]) -> None:
    header = f'{timestamp} {fd:>5}'
    inode = info['inode'] if 'inode' in info else ''
    itype = info['type'] if 'type' in info else ''
    l_addr_port = hex_ip6_port(info['local'])
    r_addr_port = hex_ip6_port(info['remote'])
    hex_st = info['st']
    st = TCP_STATES[hex_st] if hex_st in TCP_STATES else hex_st
    cprint(
        update_type,
        header +
        f' {update_type}{itype:<6} {inode:>10} {l_addr_port} {r_addr_port} {st}')
def display_unix(timestamp : str, update_type : str, fd : str,
                 info: Dict[str, Any]) -> None:
    header = f'{timestamp} {fd:>5}'
    inode = info['inode']
    flags = info['flags'] if 'flags' in info else ''
    path = info['path']
    hex_stype = info['stype']
    hex_st = info['st']
    itype = 'UNIX'
    usocktype = ("STREAM" if hex_stype == "0001" else
                 "DGRAM" if hex_stype == "0002" else
                 "SEQPACKET" if hex_stype == "0005" else
                 hex_stype)
    st = ("UNCONNECTED" if hex_st == "01" else
          "CONNECTING" if hex_st == "02" else
          "CONNECTED" if hex_st == "03" else
          "DISCONNECTING" if hex_st == "04" else
          hex_st)
    cprint(
        update_type,
        header +
        f' {update_type}{itype:<6} {usocktype:<10} {st:<15} {path}')

def display_pipe(timestamp : str, update_type : str, fd : str,
                 info : Dict[str, str]) -> None:
    itype = 'PIPE'
    cdisplay(update_type, timestamp, fd, itype, info)

def display_epoll_events(first : bool, s : str, update : str,
                         tfd : str, entry : Dict[str, str]) -> None:
    hex_events = entry['events'] if 'events' in entry else ''
    events = decode_epoll_events(hex_events)
    if first:
        cprint(update, f'{s} {update}{tfd:>5} {events}')
    else:
        cprint(update, ' ' * len(s) + f' {update}{tfd:>5} {events}')

def display_epoll(timestamp : str, update_type : str,
                  fd : str, info : Dict[str, Any]) -> None:
    header = f'{timestamp} {fd:>5}'
    itype = 'EPOLL'
    inode = info['inode'] if 'inode' in info else ''
    flags = info['flags'] if 'flags' in info else ''
    s = header + f' {update_type}{itype:<6} {inode:>10} '
    tfd_entry_map = info['tfds'] if 'tfds' in info else {}
    first = True
    for tfd in sorted(tfd_entry_map.keys(), key = int):
        entry = tfd_entry_map[tfd]
        display_epoll_events(first, s, update_type, tfd, entry)
        first = False

def display_epoll_change(timestamp : str, update_type : str,
                         fd : str, itype : str,
                         new_info : Dict[str, Any],
                         old_info : Dict[str, Any]) -> None:
    header = f'{timestamp} {fd:>5}'
    new_inode = new_info['inode'] if 'inode' in new_info else ''
    new_s = f'{header} {update_type}{itype:<6} {new_inode:>10} '
    old_inode = old_info['inode'] if 'inode' in old_info else ''
    old_s = f'{header} {update_type}{itype:<6} {old_inode:>10} '
    new_tfd_entry_map = new_info['tfds'] if 'tfds' in new_info else {}
    old_tfd_entry_map = old_info['tfds'] if 'tfds' in old_info else {}
    first = True
    tfds = set(new_tfd_entry_map.keys()).union(old_tfd_entry_map.keys())
    for tfd in sorted(tfds, key = int):
        if tfd in new_tfd_entry_map:
            new_entry = new_tfd_entry_map[tfd]
            if tfd not in old_tfd_entry_map:
                display_epoll_events(first, new_s, '+',
                                     tfd, new_entry)
            else:
                old_entry = old_tfd_entry_map[tfd]
                if new_entry == old_entry:
                    display_epoll_events(first, new_s,
                                         '=', tfd, new_entry)
                else:
                    display_epoll_events(first, old_s,
                                         '-', tfd, old_entry)
                    display_epoll_events(False, new_s,
                                         '+', tfd, new_entry)
        else:
            old_entry = old_tfd_entry_map[tfd]
            display_epoll_events(first, old_s,
                                 '-', tfd, old_entry)
        first = False

def display_event(timestamp : str, update_type : str, fd : str,
                  info : Dict[str, str]) -> None:
    itype = 'EVENT'
    cdisplay(update_type, timestamp, fd, itype, info)

def display_timer(timestamp : str, update_type : str, fd : str,
                  info : Dict[str, str]) -> None:
    itype = 'TIMER'
    cdisplay(update_type, timestamp, fd, itype, info)

def display_file(timestamp : str, update_type : str, fd : str,
                 info : Dict[str, str]) -> None:
    itype = 'FILE'
    cdisplay(update_type, timestamp, fd, itype, info)

def display_new_delete(timestamp : str, u_type: str, fd : str, itype : str,
                       info : Dict[str, Any]) -> None:
    if itype == 'UNKNOWN':
        display_unknown(timestamp, u_type, fd, info)
    elif itype == 'SOCKET':
        display_socket(timestamp, u_type, fd, info)
    elif itype in ('UDP', 'TCP'):
        display_net(timestamp, u_type, fd, info)
    elif itype in ('UDP6', 'TCP6'):
        display_net6(timestamp, u_type, fd, info)
    elif itype == 'UNIX':
        display_unix(timestamp, u_type, fd, info)
    elif itype == 'PIPE':
        display_pipe(timestamp, u_type, fd, info)
    elif itype == 'EPOLL':
        display_epoll(timestamp, u_type, fd, info)
    elif itype == 'EVENT':
        display_event(timestamp, u_type, fd, info)
    elif itype == 'TIMER':
        display_timer(timestamp, u_type, fd, info)
    elif itype == 'FILE':
        display_file(timestamp, u_type, fd, info)
    else:
        print(f'unknown itype[{itype}]', file = sys.stderr)
def display_change(timestamp : str, fd : str,
                   new_info : Dict[str, Any],
                   old_info : Dict[str, Any]) -> None:
    new_itype = new_info['type'] if 'type' in new_info else ''
    old_itype = old_info['type'] if 'type' in old_info else ''
    if new_itype == old_itype and new_itype == 'EPOLL':
        display_epoll_change(
            timestamp, '>', fd, new_itype, new_info, old_info)
    else:
        display_new_delete(timestamp, '-', fd, old_itype, old_info)
        display_new_delete(timestamp, '+', fd, new_itype, new_info)
def display(event : Dict[str, Any]) -> None:
    timestamp = event['timestamp']
    fd = event['fd']
    updateType = event['updateType']
    if updateType == 'NEW':
        new_info = event['new']
        new_itype = new_info['type'] if 'type' in new_info else ''
        display_new_delete(timestamp, '+', fd, new_itype, new_info)
    elif updateType == 'CHANGE':
        display_change(timestamp, fd, event['new'], event['old'])
    elif updateType == 'DELETE':
        old_info = event['old']
        old_itype = old_info['type'] if 'type' in old_info else ''
        display_new_delete(timestamp, '-', fd, old_itype, old_info)
    else:
        print(f'unknown updateType[{updateType}]', file = sys.stderr)
def main() -> None:
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                display(event)
            except json.JSONDecodeError:
                print(line, file = sys.stderr)
                traceback.print_exc(file = sys.stderr)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
