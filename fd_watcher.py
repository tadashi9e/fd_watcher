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
    from typing import Any, Optional
except:
    pass

# ----------------------------------------------------------------------
class info_type(Enum):
    UNKNOWN = 0
    UDP = 1
    TCP = 2
    UDP6 = 3
    TCP6 = 4
    UNIX = 5
    PIPE = 6
    EPOLL = 7
    FILE = 8

class Info(ABC):
    def __init__(self, itype : info_type):
        self.itype = itype
    @abstractmethod
    def clone(self) -> 'Info':
        pass
    @abstractmethod
    def to_obj(self) -> dict[str, Any]:
        pass
class UnknownInfo(Info):
    def __init__(self, inode : str, raw : str):
        super().__init__(info_type.UNKNOWN)
        self.inode = inode
        self.raw = raw
    def clone(self) -> 'UnknownInfo':
        return UnknownInfo(self.inode, self.raw)
    def __eq__(self, other : object) -> bool:
        if not isinstance(other, UnknownInfo):
            return False
        return (self.itype == other.itype and
                self.inode == other.inode and
                self.raw == other.raw)
    def to_obj(self) -> dict[str, str]:
        return {'type': self.itype.name,
                'inode': self.inode,
                'raw': self.raw}
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
    def to_obj(self) -> dict[str, str]:
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
        return (self.inode == other.inode and
                self.path == other.path and
                self.stype == other.stype and
                self.st == other.st)
    def to_obj(self) -> dict[str, str]:
        return {'type': self.itype.name,
                'inode': self.inode,
                'path': self.path,
                'stype': self.stype,
                'st': self.st}
class PipeInfo(Info):
    def __init__(self, inode : str):
        super().__init__(info_type.PIPE)
        self.inode = inode
    def clone(self) -> 'PipeInfo':
        return PipeInfo(self.inode)
    def __eq__(self, other : object) -> bool:
        if not isinstance(other, PipeInfo):
            return False
        return self.inode == other.inode
    def to_obj(self) -> dict[str, str]:
        return {'type': self.itype.name,
                'inode': self.inode}
class EpollInfo(Info):
    def __init__(self, inode : str, fd_info : dict[str, str]):
        super().__init__(info_type.EPOLL)
        self.inode = inode
        self.fd_info = fd_info
    def clone(self) -> 'EpollInfo':
        return EpollInfo(self.inode, dict(self.fd_info))
    def __eq__(self, other : object) -> bool:
        if not isinstance(other, EpollInfo):
            return False
        return (self.inode == other.inode and
                self.fd_info == other.fd_info)
    def to_obj(self) -> dict[str, Any]:
        return {'type': self.itype.name,
                'inode': self.inode,
                'events': self.fd_info}
class FileInfo(Info):
    def __init__(self, target : str):
        super().__init__(info_type.FILE)
        self.target = target
    def clone(self) -> 'FileInfo':
        return FileInfo(self.target)
    def __eq__(self, other : object) -> bool:
        if not isinstance(other, FileInfo):
            return False
        return self.target == other.target
    def to_obj(self) -> dict[str, str]:
        return {'type': self.itype.name,
                'target': self.target}
def get_inode(s : str) -> str:
    i1 = s.find('[')
    i2 = s.find(']')
    if i1 == -1 or i2 == -1:
        return s
    return s[i1 + 1:i2]

def append_net_info(itype : info_type, path : str,
                    inode_info_map : dict[str , Info]) -> None:
    with open(path) as f:
        is_header = True
        for line in f:
            if is_header:
                is_header = False
                continue
            fields = re.split(r'\s+', line)
            if len(fields) < 10:
                continue
            (hex_local, hex_remote, hex_st, inode) = (
                fields[1], fields[2], fields[3], fields[9])
            inode_info_map[inode] = TcpUdpInfo(
                itype, inode, hex_local, hex_remote, hex_st)

def append_tcp_info(pid : str, inode_info_map : dict[str, Info]) -> None:
    append_net_info(info_type.TCP, f'/proc/{pid}/net/tcp',
                    inode_info_map)
def append_udp_info(pid : str, inode_info_map : dict[str, Info]) -> None:
    append_net_info(info_type.UDP, f'/proc/{pid}/net/udp',
                    inode_info_map)
def append_tcp6_info(pid : str, inode_info_map : dict[str, Info]) -> None:
    append_net_info(info_type.TCP6, f'/proc/{pid}/net/tcp6',
                    inode_info_map)
def append_udp6_info(pid : str, inode_info_map : dict[str, Info]) -> None:
    append_net_info(info_type.UDP6, f'/proc/{pid}/net/udp6',
                    inode_info_map)
def append_unix_info(pid : str, inode_info_map : dict[str, Info]) -> None:
    path = f'/proc/{pid}/net/unix'
    with open(path) as f:
        is_header = True
        for line in f:
            if is_header:
                is_header = False
                continue
            fields = re.split(r'\s+', line)
            if len(fields) < 7:
                continue
            (hex_type, hex_st, inode) = (
                fields[4], fields[5], fields[6])
            raw_path = fields[7] if len(fields) > 7 else ''
            inode_info_map[inode] = UnixInfo(
                inode, raw_path, hex_type, hex_st)
def read_fdinfo(pid : str, fd : str) -> Optional[EpollInfo]:
    path = f'/proc/{pid}/fdinfo/{fd}'
    try:
        inode = ''
        fd_info : dict[str, str] = {}
        with open(path) as f:
            for line in f:
                fields = line.split()
                if fields[0] == 'ino:':
                    inode = fields[1]
                elif fields[0] == 'tfd:':
                    tfd = fields[1]
                    if 'events:' in fields:
                        idx = fields.index('events:')
                        events = fields[idx + 1]
                        fd_info[tfd] = events
        return EpollInfo(inode, fd_info)
    except FileNotFoundError:
        return None
# ----------------------------------------------------------------------
class action_type(Enum):
    NEW = 1
    UPDATE = 2
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
        self.change_fd_action_map : dict[str, Action] = {}
    def act_new(self, fd : str, new_info : Info) -> None:
        self.change_fd_action_map[fd] = Action(
            action_type.NEW, None, new_info)
    def act_update(self, fd : str,
                   old_info : Info, new_info : Info) -> None:
        self.change_fd_action_map[fd] = Action(
            action_type.UPDATE, old_info, new_info)
    def act_delete(self, fd : str, old_info : Info) -> None:
        self.change_fd_action_map[fd] = Action(
            action_type.DELETE, old_info, None)
    def report(self) -> None:
        for fd, action in self.change_fd_action_map.items():
            item : dict[str, Any] = {
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
        self.fd_info_map : dict[str, Info] = {}
    def snapshot(self, pid : str) -> None:
        self.fd_info_map = {}
        inode_info_map : dict[str, Info] = {}
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
                    b = self._update_fd_info_map(fd, inode, inode_info_map)
                    if b:
                        continue
                    self.fd_info_map[fd] = UnknownInfo(inode, target)
                    continue
                if 'pipe:[' in target:
                    inode = get_inode(target)
                    self.fd_info_map[fd] = PipeInfo(inode)
                    continue
                if target == 'anon_inode:[eventpoll]':
                    fd_info = read_fdinfo(pid, fd)
                    if fd_info:
                        self.fd_info_map[fd] = fd_info
                        continue
                self.fd_info_map[fd] = FileInfo(target)
            except FileNotFoundError:
                continue
    def _update_fd_info_map(self, fd : str, inode : str,
                            inode_info_map : dict[str, Info]) -> bool:
        if inode not in inode_info_map:
            return False
        self.fd_info_map[fd] = inode_info_map[inode].clone()
        return True
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
                diff.act_update(fd, old_info, new_info)
            else:
                diff.act_new(fd, new_info)
            self.fd_info_map[fd] = new_info
        return diff

def main() -> None:
    try:
        if len(sys.argv) != 2:
            print(f'usage: {sys.argv[0]} PID', file = sys.stderr)
            sys.exit(1)
        pid = sys.argv[1]
        summary_snapshot = Snapshot()
        while True:
            current_snapshot = Snapshot()
            current_snapshot.snapshot(pid)
            timestamp = datetime.datetime.now()
            difference = summary_snapshot.update_to(
                current_snapshot, timestamp)
            difference.report()
            time.sleep(1)
    except:
        traceback.print_exc(file = sys.stderr)

if __name__ == '__main__':
    main()
