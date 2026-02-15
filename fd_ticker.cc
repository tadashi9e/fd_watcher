// -*- coding: utf-8; mode:c++ -*-
#include <arpa/inet.h>
#include <dirent.h>
#include <linux/eventpoll.h>
#include <ncurses.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

enum lru_state {
  S_DELETE,
  S_ACTIVE,
  S_CHANGE,
  S_NEW,
};

static std::string
hex_ip_port(const std::string& hex) {
  uint32_t ip;
  uint16_t port;
  sscanf(hex.c_str(), "%8X:%4hX", &ip, &port);
  uint32_t h = ntohl(ip);
  const int b4 = h & 0xff;
  const int b3 = (h >> 8) & 0xff;
  const int b2 = (h >> 16) & 0xff;
  const int b1 = (h >> 24) & 0xff;
  const uint16_t p = ntohs(port);
  std::stringstream ss;
  ss << b1 << "." << b2 << "." << b3 << "." << b4 << ":" << p;
  return ss.str();
}
static std::string
hex_ip6_port(const std::string& hex)
{
  if (hex.size() < 37) {
    return "?";
  }

  std::string addr_hex = hex.substr(0, 32);
  std::string port_hex = hex.substr(33);

  struct in6_addr addr;
  memset(&addr, 0, sizeof(addr));

  for (int i = 0; i < 4; ++i) {
    uint32_t word;
    std::string block = addr_hex.substr(i * 8, 8);
    if (sscanf(block.c_str(), "%8X", &word) != 1) {
      return "?";
    }
    word = ntohl(word);
    memcpy(&addr.s6_addr[i * 4], &word, 4);
  }

  char buf[INET6_ADDRSTRLEN];
  if (!inet_ntop(AF_INET6, &addr, buf, sizeof(buf))) {
    return "?";
  }

  uint16_t port;
  if (sscanf(port_hex.c_str(), "%4hX", &port) != 1) {
    return "?";
  }
  const uint16_t p = ntohs(port);
  std::stringstream ss;
  ss << "[" << buf << "]:" << p;
  return ss.str();
}

static std::string
net_state(const std::string& hex) {
  static std::unordered_map<std::string, std::string> m = {
    {"01", "ESTABLISHED"},
    {"02", "SYN_SENT"},
    {"03", "SYN_RECV"},
    {"04", "FIN_WAIT1"},
    {"05", "FIN_WAIT2"},
    {"06", "TIME_WAIT"},
    {"07", "CLOSE"},
    {"08", "CLOSE_WAIT"},
    {"09", "LAST_ACK"},
    {"0A", "LISTEN"},
    {"0B", "CLOSING"}
  };
  return m.count(hex) ? m[hex] : "UNKNOWN";
}
enum net_type {
  N_UNKNOWN,
  N_UDP,
  N_TCP,
  N_UDP6,
  N_TCP6,
  N_UNIX,
  N_EPOLL,
};
static const char*
net_type_str(net_type type) {
  switch (type) {
  case N_UDP: return "UDP";
  case N_TCP: return "TCP";
  case N_UDP6: return "UDP6";
  case N_TCP6: return "TCP6";
  case N_UNIX: return "UNIX";
  case N_EPOLL: return "EPOLL";
  default:
    return "?";
  }
}

using timestamp_t = std::chrono::time_point<std::chrono::system_clock>;

static std::string
timestamp_str(const timestamp_t& timestamp) {
  std::time_t t = std::chrono::system_clock::to_time_t(timestamp);
  std::tm tm;
  localtime_r(&t, &tm);
  char buffer[80];
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
  return buffer;
}

struct FdInfoEntry {
  std::string events;
  std::string old_events;
  lru_state state;
  timestamp_t timestamp;
  timestamp_t old_timestamp;
  FdInfoEntry() : state(S_DELETE) {
  }
  explicit FdInfoEntry(std::string events)
    : events(events), state(S_NEW) {
    timestamp = std::chrono::system_clock::now();
  }
  void update_to(const FdInfoEntry& new_entry) {
    if (events == new_entry.events) {
      state = S_ACTIVE;
      return;
    }
    old_events = events;
    events = new_entry.events;
    state = S_CHANGE;
    old_timestamp = timestamp;
    timestamp = new_entry.timestamp;
  }
};
struct FdInfo {
  std::map<int, FdInfoEntry> fd_event_map;
  void set(int fd, const std::string& events) {
    fd_event_map[fd] = FdInfoEntry(events);
  }
  void update_to(const FdInfo& new_fd_info) {
    for (auto v : fd_event_map) {
      FdInfoEntry& entry = v.second;
      entry.state = S_DELETE;
    }
    for (auto v : new_fd_info.fd_event_map) {
      const int fd = v.first;
      const FdInfoEntry& new_entry = v.second;
      auto it = fd_event_map.find(fd);
      if (it == fd_event_map.end()) {
        fd_event_map.insert({fd, FdInfoEntry(new_entry.events)});
      } else {
        FdInfoEntry& entry = it->second;
        entry.update_to(new_entry);
      }
    }
  }
  bool operator==(const FdInfo& others) const {
    if (fd_event_map.size() != others.fd_event_map.size()) {
      return false;
    }
    for (auto v : fd_event_map) {
      const int tfd = v.first;
      const FdInfoEntry& entry = v.second;
      auto it = others.fd_event_map.find(tfd);
      if (it == others.fd_event_map.end()) {
        return false;
      }
      const FdInfoEntry& entry2 = it->second;
      if (entry.events != entry2.events) {
        return false;
      }
    }
    return true;
  }
};
struct NetInfo {
  int64_t inode;
  net_type type;
  std::string local;
  std::string remote;
  std::string state;
  FdInfo fd_info;
  NetInfo() : inode(-1) {}
  NetInfo(int64_t inode,
          net_type type,
          std::string local,
          std::string remote,
          std::string state)
    : inode(inode), type(type), local(local), remote(remote),
      state(state) {
  }
  NetInfo(int64_t inode,
          net_type type,
          const FdInfo& fd_info)
    : inode(inode), type(type), fd_info(fd_info) {
  }
  void update_to(const NetInfo& new_net_info) {
    inode = new_net_info.inode;
    type = new_net_info.type;
    local = new_net_info.local;
    remote = new_net_info.remote;
    state = new_net_info.state;
    fd_info.update_to(new_net_info.fd_info);
  }
  explicit operator bool() const {
    return inode != -1;
  }
  bool operator==(const NetInfo& others) const {
    if (type != others.type) {
      return false;
    }
    if (type == N_EPOLL) {
      return fd_info == others.fd_info;
    } else {
      return
        inode == others.inode &&
        type == others.type &&
        local == others.local &&
        remote == others.remote &&
        state == others.state;
    }
  }
};
static std::unordered_map<int64_t, NetInfo>
read_net(const std::string& pid,
         const std::string& path,
         const net_type type) {
  std::ifstream f(path);
  std::unordered_map<int64_t, NetInfo> out;
  std::string line;
  getline(f, line);  // header

  while (getline(f, line)) {
    std::istringstream iss(line);
    std::vector<std::string> fields;
    {
      std::string t;
      while (iss >> t) {
        fields.push_back(t);
      }
    }
    if (fields.size() < 10) {
      continue;
    }
    const std::string local = fields[1];
    const std::string remote = fields[2];
    const std::string st = fields[3];
    const int64_t inode = std::stoll(fields[9]);
    if (inode == 0) {
      continue;
    }
    out[inode] = NetInfo(inode, type,
                         hex_ip_port(local),
                         hex_ip_port(remote),
                         net_state(st));
  }
  return out;
}
static std::unordered_map<int64_t, NetInfo>
read_net6(const std::string& pid,
          const std::string& path,
          const net_type type) {
  std::ifstream f(path);
  std::unordered_map<int64_t, NetInfo> out;
  std::string line;
  getline(f, line);  // header

  while (getline(f, line)) {
    std::istringstream iss(line);
    std::vector<std::string> fields;
    {
      std::string t;
      while (iss >> t) {
        fields.push_back(t);
      }
    }
    if (fields.size() < 10) {
      continue;
    }
    const std::string local = fields[1];
    const std::string remote = fields[2];
    const std::string st = fields[3];
    const int64_t inode = std::stoll(fields[9]);
    if (inode == 0) {
      continue;
    }
    out[inode] = NetInfo(inode, type,
                         hex_ip6_port(local),
                         hex_ip6_port(remote),
                         net_state(st));
  }
  return out;
}
static std::unordered_map<int64_t, NetInfo>
read_tcp(const std::string& pid) {
  return read_net(pid, "/proc/" + pid + "/net/tcp", N_TCP);
}
static std::unordered_map<int64_t, NetInfo>
read_udp(const std::string& pid) {
  return read_net(pid, "/proc/" + pid + "/net/udp", N_UDP);
}
static std::unordered_map<int64_t, NetInfo>
read_tcp6(const std::string& pid) {
  return read_net6(pid, "/proc/" + pid + "/net/tcp6", N_TCP6);
}
static std::unordered_map<int64_t, NetInfo>
read_udp6(const std::string& pid) {
  return read_net6(pid, "/proc/" + pid + "/net/udp6", N_UDP6);
}
static std::unordered_map<int64_t, NetInfo>
read_unix(const std::string& pid) {
  std::ifstream f("/proc/" + pid + "/net/unix");
  std::unordered_map<int64_t, NetInfo> out;
  std::string line;
  getline(f, line);  // header
  while (getline(f, line)) {
    std::istringstream iss(line);
    std::vector<std::string> fields;
    std::string t;
    while (iss >> t) {
      fields.push_back(t);
    }
    if (fields.size() < 7) continue;
    const std::string type_hex = fields[4];
    const std::string st_hex   = fields[5];
    const int64_t inode = std::stoll(fields[6]);
    if (inode == 0) {
      continue;
    }
    const std::string raw_path =
      (fields.size() >= 8) ? fields[7] : "";
    const std::string path =
      raw_path.empty() ? "(anonymous)" : ("[" + raw_path + "]");
    const std::string type_str =
      (type_hex == "0001") ? "STREAM" :
      (type_hex == "0002") ? "DGRAM" :
      (type_hex == "0005") ? "SEQPACKET" :
      type_hex;
    const std::string state_str =
      (st_hex == "01") ? "UNCONNECTED" :
      (st_hex == "02") ? "CONNECTING" :
      (st_hex == "03") ? "CONNECTED" :
      (st_hex == "04") ? "DISCONNECTING" :
      st_hex;
    out[inode] = NetInfo(inode, N_UNIX, type_str + path, "",
                         state_str);
  }
  return out;
}
// ----------------------------------------------------------------------
enum info_type {
  I_NONE,
  I_FILE,
  I_NET,
};
struct Info {
  int fd;
  info_type type;
  std::string content_str;
  NetInfo     content_net;
  bool enable;
  lru_state state;
  timestamp_t timestamp;
  struct Old {
    info_type type;
    std::string content_str;
    NetInfo     content_net;
    timestamp_t timestamp;
  } old;
  Info()
    : fd(-1), type(I_NONE) {
  }
  Info(int fd, const std::string& s)
    : fd(fd), type(I_FILE), content_str(s), enable(true), state(S_NEW) {
    timestamp = std::chrono::system_clock::now();
  }
  Info(int fd, const NetInfo& info)
    : fd(fd), type(I_NET), content_net(info), enable(true), state(S_NEW) {
    timestamp = std::chrono::system_clock::now();
  }
  void update_to(const Info& new_info) {
    switch (type) {
    case I_NONE:
      break;
    case I_FILE:
      old.type = I_FILE;
      old.content_str = content_str;
      break;
    case I_NET:
      old.type = I_NET;
      old.content_net = content_net;
      break;
    }
    type = new_info.type;
    switch (new_info.type) {
    case I_NONE:
      break;
    case I_FILE:
      content_str = new_info.content_str;
      break;
    case I_NET:
      content_net.update_to(new_info.content_net);
      break;
    }
    state = S_CHANGE;
    old.timestamp = timestamp;
    timestamp = new_info.timestamp;
  }
  int display(int row) {
    mvprintw(row, 0, "%s", timestamp_str(timestamp).c_str());
    mvprintw(row, 20, "%d", fd);
    switch (type) {
    case I_NONE:
      ++row;
      break;
    case I_FILE:
      mvprintw(row, 25, "%s",  "FILE");
      mvprintw(row, 32, "%s",
               trim(COLS-10-1, content_str).c_str());
      ++row;
      break;
    case I_NET:
      mvprintw(row, 25, "%s",  net_type_str(content_net.type));
      mvprintw(row, 32, "%lld",
               static_cast<long long>(content_net.inode));
      if (content_net.type == N_EPOLL) {
        for (auto v : content_net.fd_info.fd_event_map) {
          const int tfd = v.first;
          const FdInfoEntry& fd_entry = v.second;
          switch (fd_entry.state) {
          case S_DELETE:
            attron(COLOR_PAIR(1));
            mvprintw(row, 0, "%s", timestamp_str(fd_entry.timestamp).c_str());
            mvprintw(row, 40, "%d", tfd);
            mvprintw(row, 45, "[%s]", fd_entry.events.c_str());
            ++row;
            break;
          case S_CHANGE:
            attron(COLOR_PAIR(3));  // new
            mvprintw(row, 0, "%s", timestamp_str(fd_entry.timestamp).c_str());
            mvprintw(row, 40, "%d", tfd);
            mvprintw(row, 45, "[%s]", fd_entry.events.c_str());
            ++row;
            attron(COLOR_PAIR(4));  // old
            mvprintw(row, 0, "%s", timestamp_str(fd_entry.old_timestamp).c_str());
            mvprintw(row, 45, "[%s]", fd_entry.old_events.c_str());
            ++row;
            break;
          case S_NEW:
            attron(COLOR_PAIR(3));
            mvprintw(row, 0, "%s", timestamp_str(fd_entry.timestamp).c_str());
            mvprintw(row, 40, "%d", tfd);
            mvprintw(row, 45, "[%s]", fd_entry.events.c_str());
            ++row;
            break;
          default:  // S_ACTIVE
            attron(COLOR_PAIR(2));
            mvprintw(row, 0, "%s", timestamp_str(fd_entry.timestamp).c_str());
            mvprintw(row, 40, "%d", tfd);
            mvprintw(row, 45, "[%s]", fd_entry.events.c_str());
            ++row;
          }
        }
      } else {
        mvprintw(row, 40, "%s", content_net.local.c_str());
        mvprintw(row, 60, "%s", content_net.remote.c_str());
        mvprintw(row, 80, "%s", content_net.state.c_str());
        ++row;
      }
      break;
    }
    return row;
  }
  int display_old(int row) {
    switch (type) {
    case I_NONE:
      break;
    case I_FILE:
      mvprintw(row, 25, "%s",  "file");
      mvprintw(row, 32, "%s",
               trim(COLS-12-1, old.content_str).c_str());
      ++row;
      break;
    case I_NET:
      mvprintw(row, 25, "%s",  net_type_str(old.content_net.type));
      mvprintw(row, 32, "%lld",
               static_cast<long long>(old.content_net.inode));
      if (old.content_net.type == N_EPOLL) {
        //
      } else {
        mvprintw(row, 40, "%s", old.content_net.local.c_str());
        mvprintw(row, 60, "%s", old.content_net.remote.c_str());
        mvprintw(row, 80, "%s", old.content_net.state.c_str());
      }
      ++row;
      break;
    }
    return row;
  }
  std::string trim(int width, const std::string& s) {
    if (width < 0) {
      return "";
    }
    if (s.length() > static_cast<size_t>(width)) {
      return s.substr(0, width - 1) + ">";
    }
    return s;
  }
  bool operator==(const Info& others) const {
    if (fd != others.fd) {
      return false;
    }
    if (type != others.type) {
      return false;
    }
    switch (type) {
    case I_NONE:
      return false;
    case I_FILE:
      return content_str == others.content_str;
    case I_NET:
      return content_net == others.content_net;
    default:
      return false;
    }
  }
};

static std::string
decode_events(const int events) {
  std::string s;
#define check(v, t)                             \
  if (events & v) {                             \
    if (!s.empty()) {                           \
      s += "|";                                 \
    }                                           \
    s += t;                                     \
  }
  check(EPOLLIN, "IN");
  check(EPOLLPRI, "PRI");
  check(EPOLLOUT, "OUT");
  check(EPOLLERR, "ERR");
  check(EPOLLHUP, "HUP");
  check(EPOLLRDNORM, "RDNORM");
  check(EPOLLRDBAND, "RDBAND");
  check(EPOLLWRNORM, "WRNORM");
  check(EPOLLWRBAND, "WRBAND");
  check(EPOLLMSG, "MSG");
  check(EPOLLRDHUP, "RDHUP");
#undef check
  return s;
}

static NetInfo
read_fdinfo(const std::string& pid, const std::string& fd) {
  std::string inode;
  FdInfo fd_info;
  const std::string path = "/proc/" + pid + "/fdinfo/" + fd;
  std::ifstream f(path);
  std::string line;
  while (getline(f, line)) {
    std::istringstream iss(line);
    std::string t;
    iss >> t;
    if (t == "tfd:") {
      std::string tfd;
      iss >> tfd;
      iss >> t;
      if (t == "events:") {
        int events;
        iss >> std::hex >> events;
        fd_info.set(stoi(tfd), decode_events(events));
      }
      continue;
    }
    if (t == "ino:") {
      iss >> inode;
    }
  }
  return NetInfo(inode.empty() ? -1 : std::stoll(inode),
                 N_EPOLL, fd_info);
}
// ----------------------------------------------------------------------

static std::list<Info>
snapshot(const std::string& pid) {
  std::list<Info> lines;
  auto inode_tcp_map = read_tcp(pid);
  auto inode_udp_map = read_udp(pid);
  auto inode_tcp6_map = read_tcp6(pid);
  auto inode_udp6_map = read_udp6(pid);
  auto inode_unix_map = read_unix(pid);

  DIR* d = opendir(("/proc/" + pid + "/fd").c_str());
  if (!d) {
    throw std::runtime_error("[cannot open fd directory]");
  }

  struct dirent* e;
  char buf[512];

  while ((e = readdir(d))) {
    if (e->d_name[0] == '.') continue;
    const std::string fd = e->d_name;
    char* endptr = nullptr;
    const int64_t n = strtol(fd.c_str(), &endptr, 10);
    if (*endptr != '\0') {
      continue;  // not a number
    }
    const int n_fd = static_cast<int>(n);
    const std::string path = "/proc/" + pid + "/fd/" + fd;
    const ssize_t len = readlink(path.c_str(), buf, sizeof(buf)-1);
    if (len < 0) continue;
    buf[len] = 0;
    std::string target(buf);

    if (target.find("socket:[") == 0) {
      const int64_t inode =
        std::stoll(target.substr(8, target.size()-9));
      {
        std::unordered_map<int64_t, NetInfo>::const_iterator
          iter = inode_tcp_map.find(inode);
        if (iter != inode_tcp_map.end()) {
          const NetInfo& net_info = iter->second;
          lines.push_back(Info(n_fd, net_info));
          continue;
        }
      }
      {
        std::unordered_map<int64_t, NetInfo>::const_iterator
          iter = inode_udp_map.find(inode);
        if (iter != inode_udp_map.end()) {
          const NetInfo& net_info = iter->second;
          lines.push_back(Info(n_fd, net_info));
          continue;
        }
      }
      {
        std::unordered_map<int64_t, NetInfo>::const_iterator
          iter = inode_tcp6_map.find(inode);
        if (iter != inode_tcp6_map.end()) {
          const NetInfo& net_info = iter->second;
          lines.push_back(Info(n_fd, net_info));
          continue;
        }
      }
      {
        std::unordered_map<int64_t, NetInfo>::const_iterator
          iter = inode_udp6_map.find(inode);
        if (iter != inode_udp6_map.end()) {
          const NetInfo& net_info = iter->second;
          lines.push_back(Info(n_fd, net_info));
          continue;
        }
      }
      {
        std::unordered_map<int64_t, NetInfo>::const_iterator
          iter = inode_unix_map.find(inode);
        if (iter != inode_unix_map.end()) {
          const NetInfo& net_info = iter->second;
          lines.push_back(Info(n_fd, net_info));
          continue;
        }
      }
      lines.push_back(Info(n_fd, NetInfo(inode, N_UNKNOWN,
                                         "?", "?", "?")));
    } else if (target.find("anon_inode:[eventpoll]") == 0) {
      lines.push_back(Info(n_fd, read_fdinfo(pid, fd)));
    } else {
      lines.push_back(Info(n_fd, target));
    }
  }
  closedir(d);
  return lines;
}

using ticker_t = std::list<Info>;

struct FdEntry {
  ticker_t::iterator it;
  explicit FdEntry(ticker_t::iterator it) : it(it) {
  }
};

int
main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "usage: " << argv[0] << " PID\n";
    return 1;
  }
  std::string pid = argv[1];

  initscr();
  noecho();
  curs_set(0);
  timeout(1000);
  start_color();
  init_pair(1, COLOR_WHITE, COLOR_BLACK); // S_DELETE
  init_pair(2, COLOR_GREEN, COLOR_BLACK);
  init_pair(3, COLOR_WHITE, COLOR_RED);  // S_NEW
  init_pair(4, COLOR_WHITE, COLOR_YELLOW); // S_CHANGE

  ticker_t ticker;
  using fd_map_t = std::unordered_map<int, FdEntry>;
  fd_map_t fd_map;

  try {
    for (;;) {
      // clear flags
      for (fd_map_t::value_type& v : fd_map) {
        FdEntry& entry = v.second;
        entry.it->enable = false;
      }
      // get snapshot
      auto snap = snapshot(pid);
      // update
      for (auto& info : snap) {
        auto iter = fd_map.find(info.fd);
        if (iter != fd_map.end()) {
          FdEntry& entry = iter->second;
          Info& old_info = *entry.it;
          if (old_info == info) {  // not updated
            old_info.enable = true;
            continue;
          }
          // updated -> move to beginning
          old_info.update_to(info);
          ticker.splice(ticker.begin(), ticker, entry.it);
          continue;
        }
        // first emergence
        ticker_t::iterator it = ticker.insert(ticker.begin(), info);
        fd_map.insert({info.fd, FdEntry(it)});
      }
      // re-display
      erase();
      int row = 0;
      for (auto& info : ticker) {
        if (row >= LINES) {
          break;
        }
        if (!info.enable || info.state == S_DELETE) {
          attron(COLOR_PAIR(1));
          row = info.display(row);
          info.state = S_DELETE;
        } else if (info.state == S_CHANGE) {
          attron(COLOR_PAIR(3));  // new line
          row = info.display(row);
          attron(COLOR_PAIR(4));  // old line
          row = info.display_old(row);
        } else if (info.state == S_NEW) {
          attron(COLOR_PAIR(3));
          row = info.display(row);
          info.state = S_ACTIVE;
        } else {
          attron(COLOR_PAIR(2));
          row = info.display(row);
        }
      }
      refresh();

      int ch = getch();
      if (ch == 'q') break;
    }
    endwin();
  } catch (const std::exception& ex) {
    endwin();
    std::cerr << ex.what() << std::endl;
  } catch (...) {
    endwin();
    std::cerr << "unknown exception" << std::endl;
  }
}
