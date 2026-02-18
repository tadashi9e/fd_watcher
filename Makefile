CXX = g++
CXXFLAGS = -std=c++11 -g -Wall -O2

all: fd_watcher fd_ticker

mypy::
	mypy --strict fd_watcher.py && mypy --strict fd_watcher.py

fd_watcher: fd_watcher.cc

fd_ticker: fd_ticker.cc
	${CXX} ${CXXFLAGS} fd_ticker.cc -lncurses -o fd_ticker
