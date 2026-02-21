fd_watcher is a real-time file descriptor monitoring tool for Linux.

Unlike lsof or ss, it:

- Correlates /proc/[PID]/fd with /proc/[PID]/net
- Decodes TCP/UDP/UNIX sockets
- Inspects epoll instances and monitored FDs
- Decodes open flags
- Displays changes as colored diffs

The watcher and the UI are separated via a JSON event stream.

Changes are displayed as colored diffs (+/-/>) for easy tracking of runtime behavior.

## Install

```
pip install .
```

## Usage

```
fdwatch <PID>
```

or

```
fd_watcher <PID> | fd_decoder | fd_viewer
```

### fd_watcher

Watch procfs and generate JSON lines.

### fd_decoder

Decode output of fd_watcher.py.


### fd_viewer

Display output of fd_decoder.py.
