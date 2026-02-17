#!/usr/bin/env python3
# -*- coding: utf-8; mode:python -*-
import sys
import json
import socket
import traceback
try:
    from typing import Any
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
}

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
}
def decode_epoll_events(events : int) -> str:
    names = []
    for b in sorted(EPOLL_EVENT_MASK):
        if events & b:
            names.append(EPOLL_EVENT_MASK[b])
    return '|'.join(names)
def cprint(update_type : str, s : str) -> None:
    if sys.stdout.isatty() and update_type in COLOR_MAP:
        print(COLOR_MAP[update_type] + s + RESET)
        return
    print(s)
def display_net(timestamp : str, update_type : str,
                fd : str, stype : str, info : dict[str, str]) -> None:
    header = f'{timestamp} {fd:>5}'
    inode = info['inode']
    l_addr_port = hex_ip_port(info['local'])
    r_addr_port = hex_ip_port(info['remote'])
    hex_st = info['st']
    st = TCP_STATES[hex_st] if hex_st in TCP_STATES else hex_st
    cprint(
        update_type,
        header +
        f' {update_type}{stype:<6} {inode:>10} {l_addr_port} {r_addr_port} {st}')

def display_net6(timestamp : str, update_type : str,
                 fd : str, stype : str, info : dict[str, str]) -> None:
    header = f'{timestamp} {fd:>5}'
    inode = info['inode']
    l_addr_port = hex_ip6_port(info['local'])
    r_addr_port = hex_ip6_port(info['remote'])
    hex_st = info['st']
    st = TCP_STATES[hex_st] if hex_st in TCP_STATES else hex_st
    cprint(
        update_type,
        header +
        f' {update_type}{stype:<6} {inode:>10} {l_addr_port} {r_addr_port} {st}')

def display_epoll_events(first : bool, s : str, update : str,
                         tfd : str, hex_events : str) -> None:
    events = decode_epoll_events(int(hex_events, 16))
    if first:
        cprint(update, f'{s} {update}{tfd:>5} {events}')
    else:
        cprint(update, ' ' * len(s) + f' {update}{tfd:>5} {events}')

def display_epoll(timestamp : str, update_type : str,
                  fd : str, stype : str, info : dict[str, Any]) -> None:
    header = f'{timestamp} {fd:>5}'
    inode = info['inode']
    s = header + f' {update_type}{stype:<6} {inode:>10} '
    events = info['events']
    first = True
    for tfd in sorted(events.keys(), key = int):
        hex_events = events[tfd]
        display_epoll_events(first, s, update_type, tfd, hex_events)
        first = False

def display_epoll_change(timestamp : str, update_type : str,
                         fd : str, stype : str,
                         new_info : dict[str, Any],
                         old_info : dict[str, Any]) -> None:
    header = f'{timestamp} {fd:>5}'
    new_inode = new_info['inode']
    new_s = f'{header} {update_type}{stype:<6} {new_inode:>10} '
    old_inode = old_info['inode']
    old_s = f'{header} {update_type}{stype:<6} {old_inode:>10} '
    new_events = new_info['events']
    old_events = old_info['events']
    first = True
    tfds = set(new_events.keys()).union(old_events.keys())
    for tfd in sorted(tfds, key = int):
        if tfd in new_events:
            new_hex_events = new_events[tfd]
            if tfd not in old_events:
                display_epoll_events(first, new_s, '+',
                                     tfd, new_hex_events)
            else:
                old_hex_events = old_events[tfd]
                if new_hex_events == old_hex_events:
                    display_epoll_events(first, new_s,
                                         '=', tfd, new_hex_events)
                else:
                    display_epoll_events(first, old_s,
                                         '-', tfd, old_hex_events)
                    display_epoll_events(False, new_s,
                                         '+', tfd, new_hex_events)
        else:
            old_hex_events = old_events[tfd]
            display_epoll_events(first, old_s,
                                 '-', tfd, old_hex_events)
        first = False

def display_unix(timestamp : str, update_type : str, fd : str,
                 info: dict[str, Any]) -> None:
    header = f'{timestamp} {fd:>5}'
    inode = info['inode']
    path = info['path']
    hex_stype = info['stype']
    hex_st = info['st']
    stype = 'UNIX'
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
        f' {update_type}{stype:<6} {inode:>10} {usocktype:<10} {st} {path}')

def display_pipe(timestamp : str, update_type : str, fd : str,
                 info : dict[str, str]) -> None:
    stype = 'PIPE'
    header = f'{timestamp} {fd:>5}'
    inode = info['inode']
    s = header + f' {update_type}{stype:<6} {inode:>10}'
    cprint(update_type, s)

def display_file(timestamp : str, update_type : str, fd : str,
                 info : dict[str, str]) -> None:
    stype = 'FILE'
    header = f'{timestamp} {fd:>5}'
    target = info['target']
    cprint(update_type,
           header + f' {update_type}{stype:<6} {target}')

def display_new(timestamp : str, fd : str,
                info : dict[str, Any]) -> None:
    itype = info['type']
    if itype in ('TCP', 'UDP'):
        display_net(timestamp, '+', fd, info['type'], info)
    elif itype in ('TCP6', 'UDP6'):
        display_net6(timestamp, '+', fd, info['type'], info)
    elif itype == 'EPOLL':
        display_epoll(timestamp, '+', fd, info['type'], info)
    elif itype == 'UNIX':
        display_unix(timestamp, '+', fd, info)
    elif itype == 'PIPE':
        display_pipe(timestamp, '+', fd, info)
    elif itype == 'FILE':
        display_file(timestamp, '+', fd, info)
def display_delete(timestamp : str, fd : str,
                   info : dict[str, Any]) -> None:
    itype = info['type']
    if itype in ('TCP', 'UDP'):
        display_net(timestamp, '-', fd, info['type'], info)
    elif itype in ('TCP6', 'UDP6'):
        display_net6(timestamp, '-', fd, info['type'], info)
    elif itype == 'EPOLL':
        display_epoll(timestamp, '-', fd, info['type'], info)
    elif itype == 'UNIX':
        display_unix(timestamp, '-', fd, info)
    elif itype == 'PIPE':
        display_pipe(timestamp, '-', fd, info)
    elif itype == 'FILE':
        display_file(timestamp, '-', fd, info)
def display_change(timestamp : str, fd : str,
                   new_info : dict[str, Any],
                   old_info : dict[str, Any]) -> None:
    new_itype = new_info['type']
    old_itype = old_info['type']
    if new_itype == old_itype and new_itype == 'EPOLL':
        display_epoll_change(
            timestamp, '>', fd, new_info['type'], new_info, old_info)
    else:
        display_delete(timestamp, fd, old_info)
        display_new(timestamp, fd, new_info)
def display(event : dict[str, Any]) -> None:
    timestamp = event['timestamp']
    fd = event['fd']
    updateType = event['updateType']
    if updateType == 'NEW':
        display_new(timestamp, fd, event['new'])
    elif updateType == 'CHANGE':
        display_change(timestamp, fd, event['new'], event['old'])
    elif updateType == 'DELETE':
        display_delete(timestamp, fd, event['old'])
def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            print(line, file = sys.stderr)
            traceback.print_exc(file = sys.stderr)
        display(event)

if __name__ == '__main__':
    main()
