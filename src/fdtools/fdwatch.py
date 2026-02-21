# -*- coding: utf-8; mode:python -*-
import subprocess
import sys

import subprocess
import sys
import signal

def main() -> None:
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} PID', file=sys.stderr)
        sys.exit(1)
    pid = sys.argv[1]
    try:
        watcher = subprocess.Popen(
            ['fd_watcher', pid], stdout=subprocess.PIPE)
        decoder = subprocess.Popen(
            ['fd_decoder'], stdin=watcher.stdout, stdout=subprocess.PIPE)
        viewer = subprocess.Popen(
            ['fd_viewer'], stdin=decoder.stdout)
        watcher.stdout.close()
        decoder.stdout.close()
        viewer.wait()
        for p in (watcher, decoder, viewer):
            try:
                p.terminate()
            except Exception:
                pass
    except KeyboardInterrupt:
        pass
main()
