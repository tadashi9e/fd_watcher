#!/usr/bin/env python3
# -*- coding: utf-8; mode:python -*-
from abc import ABC, abstractmethod
import datetime
from enum import Enum
import json
import os
import re
import socket
import sys
import time
import traceback

try:
    from typing import Any, Dict, Optional
except:
    pass

# ----------------------------------------------------------------------
class info_type(Enum):
    UNKNOWN = 0
    SOCKET = 1
    UDP = 2
    TCP = 3
    UDP6 = 4
    TCP6 = 5
    UNIX = 6
    PIPE = 7
    EPOLL = 8
    EVENT = 9
    TIMER = 10
    FILE = 11

class Info(ABC):
    def __init__(self, itype : info_type):
        self.itype = itype
    @abstractmethod
    def clone(self) -> 'Info':
        pass
    @abstractmethod
    def to_obj(self) -> Dict[str, Any]:
        pass
class UnknownInfo(Info):
    def __init__(self) -> None:
        super().__init__(info_type.UNKNOWN)
    def clone(self) -> 'UnknownInfo':
        return UnknownInfo()
    def __eq__(self, other : object) -> bool:
        if not isinstance(other, UnknownInfo):
            return False
        return self.itype == other.itype
    def to_obj(self) -> Dict[str, str]:
        return {'type': self.itype.name}
class SocketInfo(Info):
    def __init__(self, inode : str, target : str):
        super().__init__(info_type.SOCKET)
        self.inode = inode
        self.target = target
    def clone(self) -> 'SocketInfo':
        return SocketInfo(self.inode, self.target)
    def __eq__(self, other : object) -> bool:
        if not isinstance(other, SocketInfo):
            return False
        return (self.itype == other.itype and
                self.target == other.target)
    def to_obj(self) -> Dict[str, str]:
        return {'type': self.itype.name,
                'inode': self.inode,
                'target': self.target}
class TcpUdpInfo(Info):
    def __init__(self, itype : info_type, inode : str,
                 local : str, remote : str, st : str):
        super().__init__(itype)
        self.inode = inode
        self.local = local
        self.remote = remote
        self.st = st
    def clone(self) -> 'TcpUdpInfo':
        return TcpUdpInfo(self.itype, self.inode,
                          self.local, self.remote, self.st)
    def __eq__(self, other : object) -> bool:
        if not isinstance(other, TcpUdpInfo):
            return False
        return (self.itype == other.itype and
                self.inode == other.inode and
                self.local == other.local and
                self.remote == other.remote and
                self.st == other.st)
    def to_obj(self) -> Dict[str, str]:
        return {'type': self.itype.name,
                'inode': self.inode,
                'local': self.local,
                'remote': self.remote,
                'st': self.st}
class UnixInfo(Info):
    def __init__(self, inode : str, path : str, stype : str, st : str):
        super().__init__(info_type.UNIX)
        self.inode = inode
        self.path = path
        self.stype = stype
        self.st = st
    def clone(self) -> 'UnixInfo':
        return UnixInfo(self.inode, self.path, self.stype, self.st)
    def __eq__(self, other : object) -> bool:
        if not isinstance(other, UnixInfo):
            return False
        return (
            self.itype == other.itype and
            self.inode == other.inode and
            self.path == other.path and
            self.stype == other.stype and
            self.st == other.st)
    def to_obj(self) -> Dict[str, str]:
        return {'type': self.itype.name,
                'inode': self.inode,
                'path': self.path,
                'stype': self.stype,
                'st': self.st}
class FdInfo(Info):
    def __init__(self, itype : info_type,
                 inode : str, target : str, flags : str,
                 tfds : Dict[str, Dict[str, Any]]):
        super().__init__(itype)
        self.inode = inode
        self.target = target
        self.flags = flags
        self.tfds = tfds
    def clone(self) -> 'FdInfo':
        return FdInfo(self.itype, self.inode, self.target, self.flags,
                      dict(self.tfds))
    def __eq__(self, other : object) -> bool:
        if not isinstance(other, FdInfo):
            return False
        return (self.inode == other.inode and
                self.target == other.target and
                self.flags == other.flags and
                self.tfds == other.tfds)
    def to_obj(self) -> Dict[str, Any]:
        obj : Dict[str, Any] = {'type': self.itype.name}
        if self.inode:
            obj['inode'] = self.inode
        if self.target:
            obj['target'] = self.target
        if self.flags:
            obj['flags'] = self.flags
        if self.tfds:
            obj['tfds'] = self.tfds
        return obj
def get_inode(s : str) -> str:
    m = re.search(r'\[(\d+)\]', s)
    return m.group(1) if m else s

def append_net_info(itype : info_type, path : str,
                    inode_info_map : Dict[str , Info]) -> None:
    with open(path) as f:
        is_header = True
        for line in f:
            if is_header:
                is_header = False
                continue
            fields = re.split(r'\s+', line)
            if fields[0] == '':
                fields = fields[1:]
            if len(fields) < 10:
                continue
            (hex_local, hex_remote, hex_st, inode) = (
                fields[1], fields[2], fields[3], fields[9])
            inode_info_map[inode] = TcpUdpInfo(
                itype, inode, hex_local, hex_remote, hex_st)

def append_tcp_info(pid : str, inode_info_map : Dict[str, Info]) -> None:
    append_net_info(info_type.TCP, f'/proc/{pid}/net/tcp',
                    inode_info_map)
def append_udp_info(pid : str, inode_info_map : Dict[str, Info]) -> None:
    append_net_info(info_type.UDP, f'/proc/{pid}/net/udp',
                    inode_info_map)
def append_tcp6_info(pid : str, inode_info_map : Dict[str, Info]) -> None:
    append_net_info(info_type.TCP6, f'/proc/{pid}/net/tcp6',
                    inode_info_map)
def append_udp6_info(pid : str, inode_info_map : Dict[str, Info]) -> None:
    append_net_info(info_type.UDP6, f'/proc/{pid}/net/udp6',
                    inode_info_map)
def append_unix_info(pid : str, inode_info_map : Dict[str, Info]) -> None:
    path = f'/proc/{pid}/net/unix'
    with open(path) as f:
        is_header = True
        for line in f:
            if is_header:
                is_header = False
                continue
            fields = re.split(r'\s+', line)
            if fields[0] == '':
                fields = fields[1:]
            if len(fields) < 7:
                continue
            (hex_type, hex_st, inode) = (
                fields[4], fields[5], fields[6])
            raw_path = fields[7] if len(fields) > 7 else ''
            inode_info_map[inode] = UnixInfo(
                inode, raw_path, hex_type, hex_st)
def read_fd_info(itype : info_type, pid : str, fd : str,
                 inode : str, target : str) -> FdInfo:
    path = f'/proc/{pid}/fdinfo/{fd}'
    flags = ''
    tfds : Dict[str, Any] = {}
    with open(path) as f:
        for line in f:
            fields = line.split()
            if fields[0] == 'flags:':
                flags = fields[1]
            elif fields[0] == 'ino:':
                inode = fields[1]
            elif fields[0] == 'tfd:':
                tfd = fields[1]
                if 'events:' in fields:
                    idx = fields.index('events:')
                    events = fields[idx + 1]
                    tfds[tfd] = {'events': events}
    return FdInfo(itype, inode, target, flags, tfds)
# ----------------------------------------------------------------------
class action_type(Enum):
    NEW = 1
    CHANGE = 2
    DELETE = 3
class Action:
    def __init__(self, atype : action_type,
                 old_info : Optional[Info],
                 new_info : Optional[Info]):
        self.atype = atype
        self.old_info = old_info
        self.new_info = new_info
class Difference:
    def __init__(self, timestamp : datetime.datetime):
        self.timestamp = timestamp
        self.change_fd_action_map : Dict[str, Action] = {}
    def act_new(self, fd : str, new_info : Info) -> None:
        self.change_fd_action_map[fd] = Action(
            action_type.NEW, None, new_info)
    def act_change(self, fd : str,
                   old_info : Info, new_info : Info) -> None:
        self.change_fd_action_map[fd] = Action(
            action_type.CHANGE, old_info, new_info)
    def act_delete(self, fd : str, old_info : Info) -> None:
        self.change_fd_action_map[fd] = Action(
            action_type.DELETE, old_info, None)
    def report(self) -> None:
        for fd in sorted(self.change_fd_action_map.keys(), key = int):
            action = self.change_fd_action_map[fd]
            item : Dict[str, Any] = {
                'timestamp':
                self.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'fd': fd,
                'updateType': action.atype.name}
            if action.old_info:
                item['old'] = action.old_info.to_obj()
            if action.new_info:
                item['new'] = action.new_info.to_obj()
            print(json.dumps(item, separators = (',', ':')))
        sys.stdout.flush()
# ----------------------------------------------------------------------
class Snapshot:
    def __init__(self) -> None:
        self.fd_info_map : Dict[str, Info] = {}
    def snapshot(self, pid : str) -> None:
        self.fd_info_map = {}
        inode_info_map : Dict[str, Info] = {}
        append_udp_info(pid, inode_info_map)
        append_tcp_info(pid, inode_info_map)
        append_udp6_info(pid, inode_info_map)
        append_tcp6_info(pid, inode_info_map)
        append_unix_info(pid, inode_info_map)
        dir_name = f'/proc/{pid}/fd'
        d = os.listdir(dir_name)
        for fd in d:
            if fd[0] == '.':
                continue
            try:
                target = os.readlink(f'{dir_name}/{fd}')
                if 'socket:[' in target:
                    inode = get_inode(target)
                    if inode in inode_info_map:
                        self.fd_info_map[fd] = inode_info_map[inode].clone()
                    else:
                        self.fd_info_map[fd] = SocketInfo(inode, target)
                    continue
                if 'pipe:[' in target:
                    inode = get_inode(target)
                    try:
                        self.fd_info_map[fd] = read_fd_info(
                            info_type.PIPE, pid, fd, inode, '')
                    except FileNotFoundError:
                        self.fd_info_map[fd] = FdInfo(
                            info_type.PIPE, inode, '', '', {})
                    continue
                if target == 'anon_inode:[eventpoll]':
                    try:
                        self.fd_info_map[fd] = read_fd_info(
                            info_type.EPOLL, pid, fd, '', '')
                    except FileNotFoundError:
                        self.fd_info_map[fd] = FdInfo(
                            info_type.EPOLL, '', '', '', {})
                    continue
                if target == 'anon_inode:[eventfd]':
                    try:
                        self.fd_info_map[fd] = read_fd_info(
                            info_type.EVENT, pid, fd, '', '')
                    except FileNotFoundError:
                        self.fd_info_map[fd] = FdInfo(
                            info_type.EVENT, '', '', '', {})
                    continue
                if target == 'anon_inode:[timerfd]':
                    self.fd_info_map[fd] = FdInfo(
                        info_type.TIMER, '', '', '', {})
                    continue
                self.fd_info_map[fd] = read_fd_info(
                    info_type.FILE, pid, fd, '', target)
            except FileNotFoundError:
                self.fd_info_map[fd] = UnknownInfo()
    def update_to(self, new_snap : 'Snapshot',
                  timestamp : datetime.datetime) -> Difference:
        diff = Difference(timestamp)
        for fd in set(self.fd_info_map) - set(new_snap.fd_info_map):
            old_info = self.fd_info_map[fd]
            del self.fd_info_map[fd]
            diff.act_delete(fd, old_info)
        for fd, new_info in new_snap.fd_info_map.items():
            if fd in self.fd_info_map:
                old_info = self.fd_info_map[fd]
                if old_info == new_info:
                    continue
                diff.act_change(fd, old_info, new_info)
            else:
                diff.act_new(fd, new_info)
            self.fd_info_map[fd] = new_info
        return diff
def fd_watcher(pid : str) -> None:
    summary_snapshot = Snapshot()
    while True:
        current_snapshot = Snapshot()
        current_snapshot.snapshot(pid)
        timestamp = datetime.datetime.now()
        difference = summary_snapshot.update_to(
            current_snapshot, timestamp)
        difference.report()
        time.sleep(1)
# ----------------------------------------------------------------------
def main() -> None:
    try:
        if len(sys.argv) != 2:
            print(f'usage: {sys.argv[0]} PID', file = sys.stderr)
            sys.exit(1)
        pid = sys.argv[1]
        fd_watcher(pid)
    except KeyboardInterrupt:
        pass
    except:
        traceback.print_exc(file = sys.stderr)
if __name__ == '__main__':
    main()
