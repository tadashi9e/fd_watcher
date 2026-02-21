#!/usr/bin/env python3
# -*- coding: utf-8; mode:python -*-
import errno
import sys
import json
import socket
import traceback
try:
    from typing import Any, Dict, Tuple
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

GENERIC = '{inode:>10} {flags:<25} {target}'
class Formatter:
    def __init__(self):
        self.HEADER = '{timestamp} {fd:>5} {update_type}{itype:<6}'
        self.UNKNOWN = GENERIC
        self.SOCKET =  GENERIC
        self.PIPE =    GENERIC
        self.EVENT =   GENERIC
        self.TIMER =   GENERIC
        self.FILE =    GENERIC
        self.NET =     '{inode:>10} {l_addr_port} {r_addr_port} {st}'
        self.UNIX =    '           {usocktype:<10} {st:<15} {path}'
        self.EPOLL =   '{inode:>10} {flags}'
        self.EPOLL_ENTRY = '{update}{tfd:>5} {events}'
# ----------------------------------------------------------------------
def cprint(update_type : str, s : str) -> None:
    if sys.stdout.isatty() and update_type in COLOR_MAP:
        print(COLOR_MAP[update_type] + s + RESET)
        return
    print(s)
def cdisplay(header_formatter : str,
             body_format : str,
             update_type : str,
             timestamp : str, fd : str, itype : str,
             info: Dict[str, Any]) -> None:
    inode = info.get('inode', '')
    flags = info.get('flags', '')
    target = info.get('target', '')
    header = header_formatter.format(
        **{'timestamp': timestamp, 'fd': fd,
           'update_type': update_type, 'itype':itype})
    body = body_format.format(**{'inode':inode, 'flags':flags, 'target':target})
    cprint(update_type, header + ' ' + body)
def display_unknown(formatter : Formatter,
                    timestamp : str, update_type : str, fd : str,
                    info: Dict[str, Any]) -> None:
    cdisplay(formatter.HEADER, formatter.UNKNOWN,
             update_type, timestamp, fd, '?', info)
def display_socket(formatter : Formatter,
                   timestamp : str, update_type : str, fd : str,
                   info: Dict[str, Any]) -> None:
    cdisplay(formatter.HEADER, formatter.SOCKET,
             update_type, timestamp, fd, 'SOCKET', info)
def display_net(formatter : Formatter,
                timestamp : str, update_type : str,
                fd : str, info : Dict[str, str]) -> None:
    itype = info.get('type', '')
    header = formatter.HEADER.format(
        **{'timestamp': timestamp, 'fd': fd,
           'update_type': update_type, 'itype': itype})
    inode = info.get('inode', '')
    l_addr_port = info.get('local', '')
    r_addr_port = info.get('remote', '')
    st = info.get('st', '')
    body = formatter.NET.format(**{
        'inode': inode,
        'l_addr_port': l_addr_port,
        'r_addr_port': r_addr_port,
        'st': st})
    cprint(update_type, header + ' ' + body)

def display_unix(formatter : Formatter,
                 timestamp : str, update_type : str, fd : str,
                 info: Dict[str, Any]) -> None:
    itype = 'UNIX'
    header = formatter.HEADER.format(
        **{'timestamp': timestamp, 'fd': fd,
           'update_type': update_type, 'itype': itype})
    inode = info.get('inode', '')
    flags = info.get('flags', '')
    path = info.get('path', '')
    hex_stype = info.get('stype', '')
    st = info.get('st', '')
    usocktype = ("STREAM" if hex_stype == "0001" else
                 "DGRAM" if hex_stype == "0002" else
                 "SEQPACKET" if hex_stype == "0005" else
                 hex_stype)
    body = formatter.UNIX.format(**{
        'usocktype': usocktype,
        'st': st,
        'path': path})
    cprint(
        update_type,
        header + ' ' + body)

def display_pipe(formatter : Formatter,
                 timestamp : str, update_type : str, fd : str,
                 info : Dict[str, str]) -> None:
    itype = 'PIPE'
    cdisplay(formatter.HEADER, formatter.PIPE,
             update_type, timestamp, fd, itype, info)

def display_epoll_entry(formatter : Formatter,
                        first : bool, s : str, update : str,
                        tfd : str, entry : Dict[str, str]) -> None:
    events = entry.get('events', '')
    body = formatter.EPOLL_ENTRY.format(
        **{'update': update, 'tfd': tfd, 'events': events})
    if first:
        cprint(update, s + ' ' + body)
    else:
        cprint(update, ' ' * len(s) + ' ' + body)

def display_epoll(formatter : Formatter,
                  timestamp : str, update_type : str,
                  fd : str, info : Dict[str, Any]) -> None:
    itype = 'EPOLL'
    header = formatter.HEADER.format(
        **{'timestamp': timestamp, 'fd': fd,
           'update_type': update_type, 'itype': itype})
    inode = info.get('inode', '')
    flags = info.get('flags', '')
    body = formatter.EPOLL.format(**{'inode': inode, 'flags': flags})
    s = header + ' ' + body
    tfd_entry_map = info.get('tfds', {})
    first = True
    for tfd in sorted(tfd_entry_map.keys(), key = int):
        entry = tfd_entry_map[tfd]
        display_epoll_entry(formatter, first, s, update_type, tfd, entry)
        first = False

def display_epoll_change(formatter : Formatter,
                         timestamp : str, update_type : str,
                         fd : str, itype : str,
                         new_info : Dict[str, Any],
                         old_info : Dict[str, Any]) -> None:
    header = formatter.HEADER.format(
        **{'timestamp': timestamp, 'fd': fd,
           'update_type': update_type, 'itype': itype})
    new_inode = new_info.get('inode', '')
    new_flags = new_info.get('flags', '')
    new_s = header + ' ' + formatter.EPOLL.format(**{
        'inode': new_inode, 'flags': new_flags})
    old_inode = old_info.get('inode', '')
    old_flags = old_info.get('flags', '')
    old_s = header + ' ' + formatter.EPOLL.format(**{
        'inode': old_inode, 'flags': old_flags})
    new_tfd_entry_map = {
        int(tfd): entry
        for tfd, entry in new_info.get('tfds', {}).items()}
    old_tfd_entry_map = {
        int(tfd): entry
        for tfd, entry in old_info.get('tfds', {}).items()}
    first = True
    tfds = set(new_tfd_entry_map.keys()).union(old_tfd_entry_map.keys())
    for tfd in sorted(tfds):
        if tfd in new_tfd_entry_map:
            new_entry = new_tfd_entry_map[tfd]
            if tfd not in old_tfd_entry_map:
                display_epoll_entry(formatter, first, new_s, '+',
                                    tfd, new_entry)
            else:
                old_entry = old_tfd_entry_map[tfd]
                if new_entry == old_entry:
                    display_epoll_entry(formatter, first, new_s,
                                        '=', tfd, new_entry)
                else:
                    display_epoll_entry(formatter, first, old_s,
                                        '-', tfd, old_entry)
                    display_epoll_entry(formatter, False, new_s,
                                        '+', tfd, new_entry)
        else:
            old_entry = old_tfd_entry_map[tfd]
            display_epoll_entry(formatter, first, old_s,
                                '-', tfd, old_entry)
        first = False

def display_event(formatter : Formatter,
                  timestamp : str, update_type : str, fd : str,
                  info : Dict[str, str]) -> None:
    itype = 'EVENT'
    cdisplay(formatter.HEADER, formatter.EVENT,
             update_type, timestamp, fd, itype, info)

def display_timer(formatter : Formatter,
                  timestamp : str, update_type : str, fd : str,
                  info : Dict[str, str]) -> None:
    itype = 'TIMER'
    cdisplay(formatter.HEADER, formatter.TIMER,
             update_type, timestamp, fd, itype, info)

def display_file(formatter : Formatter,
                 timestamp : str, update_type : str, fd : str,
                 info : Dict[str, str]) -> None:
    itype = 'FILE'
    cdisplay(formatter.HEADER, formatter.FILE,
             update_type, timestamp, fd, itype, info)

DISPLAY_NEW_DELETE = {
    'UNKNOWN': display_unknown,
    'SOCKET': display_socket,
    'UDP': display_net,
    'TCP': display_net,
    'UDP6': display_net,
    'TCP6': display_net,
    'UNIX': display_unix,
    'PIPE': display_pipe,
    'EPOLL': display_epoll,
    'EVENT': display_event,
    'TIMER': display_timer,
    'FILE': display_file}
def display_new_delete(formatter : Formatter,
                       timestamp : str, u_type: str, fd : str, itype : str,
                       info : Dict[str, Any]) -> None:
    if itype in DISPLAY_NEW_DELETE:
        DISPLAY_NEW_DELETE[itype](formatter, timestamp, u_type, fd, info)
    else:
        print(f'unknown itype[{itype}]', file = sys.stderr)
def display_change(formatter : Formatter,
                   timestamp : str, fd : str,
                   new_info : Dict[str, Any],
                   old_info : Dict[str, Any]) -> None:
    new_itype = new_info.get('type', '')
    old_itype = old_info.get('type', '')
    if new_itype == old_itype and new_itype == 'EPOLL':
        display_epoll_change(
            formatter, timestamp, '>', fd, new_itype, new_info, old_info)
    else:
        display_new_delete(formatter, timestamp, '-', fd, old_itype, old_info)
        display_new_delete(formatter, timestamp, '+', fd, new_itype, new_info)
def display(formatter : Formatter,
            event : Dict[str, Any]) -> None:
    timestamp = event.get('timestamp', '')
    fd = event.get('fd', '')
    updateType = event.get('updateType', '')
    if updateType == 'NEW':
        new_info = event.get('new', {})
        new_itype = new_info.get('type', '')
        display_new_delete(formatter, timestamp, '+', fd, new_itype, new_info)
    elif updateType == 'CHANGE':
        new_info = event.get('new', {})
        old_info = event.get('old', {})
        display_change(formatter, timestamp, fd, new_info, old_info)
    elif updateType == 'DELETE':
        old_info = event.get('old', {})
        old_itype = old_info.get('type', '')
        display_new_delete(formatter, timestamp, '-', fd, old_itype, old_info)
    else:
        print(f'unknown updateType[{updateType}]', file = sys.stderr)
# ----------------------------------------------------------------------
def main() -> None:
    try:
        formatter = Formatter()
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                display(formatter, event)
            except json.JSONDecodeError:
                print(line, file = sys.stderr)
                traceback.print_exc(file = sys.stderr)
    except KeyboardInterrupt:
        pass
    except socket.error as e:
        if e.errno != errno.EPIPE:
            raise

if __name__ == '__main__':
    main()
