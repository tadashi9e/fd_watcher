fd_watcher is a real-time file descriptor monitoring tool for Linux processes.

It inspects /proc/[PID]/fd and correlates socket inodes with /proc/[PID]/net
entries to provide human-readable output for:

- Regular files
- TCP/UDP (IPv4/IPv6)
- UNIX domain sockets
- epoll instances (including monitored FDs and event masks)

Changes are displayed as colored diffs (+/-/>) for easy tracking of runtime behavior.

## Usage

```
fd_watcher <PID> | fd_viewer.py
```
