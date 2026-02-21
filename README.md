fd_watcher is a real-time file descriptor monitoring tool for Linux.

Unlike lsof or ss, it:

- Correlates /proc/[PID]/fd with /proc/[PID]/net
- Decodes TCP/UDP/UNIX sockets
- Inspects epoll instances and monitored FDs
- Decodes open flags
- Displays changes as colored diffs

The watcher and the UI are separated via a JSON event stream.

Changes are displayed as colored diffs (+/-/>) for easy tracking of runtime behavior.

## Usage

```
fd_view <PID>
```

or

```
fd_watcher.py <PID> | fd_decoder.py | fd_viewer.py
```

### fd_watcher.py

Watch procfs and generate JSON lines.

### fd_decoder.py

Decode output of fd_watcher.py.


### fd_viewer.py

Display output of fd_decoder.py.

