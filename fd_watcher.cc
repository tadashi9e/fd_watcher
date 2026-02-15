// -*- coding: utf-8; mode:c++ -*-
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

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
  const int ms =
    std::chrono::time_point_cast<std::chrono::milliseconds>(timestamp)
    .time_since_epoch().count() % 1000;
  std::stringstream ss;
  ss << buffer << "." << std::setw(3) << std::setfill('0') << ms;
  return ss.str();
}

// escape JSON string
static std::string
jstr(const std::string& s) {
  std::string result;
  result.reserve(s.length() * 2);
  for (size_t i = 0; i < s.length(); ++i) {
    const char c = s[i];
    switch (c) {
    case '\n': result += "\\n"; break;
    case '\r': result += "\\r"; break;
    case '\t': result += "\\t"; break;
    case '"': result += "\\\""; break;
    case '\\': result += "\\\\"; break;
    case '/': result += "\\/"; break;
    default:
      result += c;
    }
  }
  return result;
}

// ----------------------------------------------------------------------

struct FdInfo {
  std::map<std::string, std::string> fd_event_map;
  void set(const std::string& fd, const std::string& events) {
    fd_event_map[fd] = events;
  }
  void update_to(const FdInfo& new_fd_info) {
    fd_event_map = new_fd_info.fd_event_map;
  }
  bool operator==(const FdInfo& others) const {
    if (fd_event_map.size() != others.fd_event_map.size()) {
      return false;
    }
    for (const auto& v : fd_event_map) {
      const std::string& tfd = v.first;
      const std::string& events = v.second;
      auto it = others.fd_event_map.find(tfd);
      if (it == others.fd_event_map.end()) {
        return false;
      }
      const std::string& events2 = it->second;
      if (events != events2) {
        return false;
      }
    }
    return true;
  }
};

std::ostream& operator<<(std::ostream& stream,
                         const FdInfo& fd_info) {
  stream << "{";
  bool first = true;
  for (const auto& v : fd_info.fd_event_map) {
    const std::string& tfd = v.first;
    const std::string& events = v.second;
    if (first) {
      first = false;
    } else {
      stream << ",";
    }
    stream << "\"" << tfd << "\":\"" << events << "\"";
  }
  stream << "}";
  return stream;
}

struct NetInfo {
  net_type type;
  std::string inode;
  std::string hex_local;
  std::string hex_remote;
  std::string hex_st;
  std::string target;
  FdInfo fd_info;
  NetInfo() : type(N_UNKNOWN) {
  }
  NetInfo(net_type type,
          const std::string& inode,
          const std::string& target)
    : type(type), inode(inode), target(target) {
  }
  NetInfo(net_type type,
          const std::string& inode,
          const std::string& hex_local,
          const std::string& hex_remote,
          const std::string& hex_st)
    : type(type), inode(inode),
      hex_local(hex_local), hex_remote(hex_remote), hex_st(hex_st) {
  }
  NetInfo(net_type type,
          const std::string& inode,
          const FdInfo& fd_info)
    : type(type), inode(inode), fd_info(fd_info) {
  }
  explicit operator bool() const {
    return type != N_UNKNOWN;
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
        hex_local == others.hex_local &&
        hex_remote == others.hex_remote &&
        hex_st == others.hex_st;
    }
  }
};
std::ostream& operator<<(std::ostream& stream,
                         const NetInfo& net_info) {
  stream << "{"
    "\"type\":\"" << net_type_str(net_info.type) << "\"";
  switch (net_info.type) {
  case N_UNKNOWN:
    stream << ",\"inode\":\"" << net_info.inode << "\""
           << ",\"raw\":\"" << jstr(net_info.target) << "\"";
    break;
  case N_UDP:
  case N_TCP:
  case N_UDP6:
  case N_TCP6:
    stream <<
      ",\"inode\":\"" << net_info.inode << "\""
      ",\"local\":\"" << net_info.hex_local << "\""
      ",\"remote\":\"" << net_info.hex_remote << "\""
      ",\"st\":\"" << net_info.hex_st << "\"";
    break;
  case N_UNIX:
    stream <<
      ",\"inode\":\"" << net_info.inode << "\""
      ",\"path\":\"" << jstr(net_info.hex_local) << "\""
      ",\"stype\":\"" << net_info.hex_remote << "\""
      ",\"st\":\"" << net_info.hex_st << "\"";
    break;
  case N_EPOLL:
    stream <<
      ",\"events\":" << net_info.fd_info;
    break;
  default:
    break;
  }
  stream << "}";
  return stream;
}

// ----------------------------------------------------------------------
enum info_type {
  I_NONE,
  I_FILE,
  I_NET,
};

struct Info {
  info_type itype;
  std::string target;
  NetInfo net_info;
  Info() : itype(I_NONE) {
  }
  explicit Info(const std::string& target)
    : itype(I_FILE), target(target) {
  }
  explicit Info(NetInfo net_info)
    : itype(I_NET), net_info(net_info) {
  }
  bool operator==(const Info& others) const {
    if (itype != others.itype) {
      return false;
    }
    switch (itype) {
    case I_FILE:
      return target == others.target;
    case I_NET:
      return net_info == others.net_info;
    default:
      return true;
    }
  }
};

std::ostream& operator<<(std::ostream& stream,
                         const Info& info) {
  switch (info.itype) {
  case I_NET:
    stream << info.net_info;
    break;
  case I_FILE:
    stream << "{"
      "\"type\":\"FILE\""
      ",\"target\":\"" << jstr(info.target) << "\""
      "}";
    break;
  default:
    stream << "{}";
    break;
  }
  return stream;
}

// ----------------------------------------------------------------------

enum action_type {
  A_NONE,
  A_NEW,
  A_UPDATE,
  A_DELETE,
};

struct Action {
  action_type atype;
  Info old_info;
  Info new_info;
  Action() : atype(A_NONE) {
  }
  Action(action_type atype, Info old_info, Info new_info)
    : atype(atype), old_info(old_info), new_info(new_info) {
  }
};

struct Difference {
  timestamp_t timestamp;
  std::map<int, Action> change_fd_action_map;
  explicit Difference(timestamp_t timestamp)
    : timestamp(timestamp) {
  }
  void act_new(int fd, const Info& info) {
    change_fd_action_map.insert({fd, Action(A_NEW, Info(), info)});
  }
  void act_update(int fd, const Info& old_info, const Info& new_info) {
    change_fd_action_map.insert({fd, Action(A_UPDATE, old_info, new_info)});
  }
  void act_delete(int fd, const Info& info) {
    change_fd_action_map.insert({fd, Action(A_DELETE, info, Info())});
  }
  void report() const {
    for (const auto& v : change_fd_action_map) {
      const int fd = v.first;
      const Action& action = v.second;
      std::cout << "{"
        "\"timestamp\":\"" << timestamp_str(timestamp) << "\""
        ",\"fd\":\"" << fd << "\"";
      switch (action.atype) {
      case A_NEW:
        std::cout << ",\"updateType\":\"NEW\""
          ",\"new\":" << action.new_info;
        break;
      case A_UPDATE:
        std::cout << ",\"updateType\":\"UPDATE\""
          ",\"old\":" << action.old_info <<
          ",\"new\":" << action.new_info;
        break;
      case A_DELETE:
        std::cout << ",\"updateType\":\"DELETE\""
          ",\"old\":" << action.old_info;
        break;
      default:
        break;
      }
      std::cout << "}\n";
    }
    std::flush(std::cout);
  }
};

// ----------------------------------------------------------------------

// "socket:[12345]" => "12345"
inline std::string get_inode(const std::string& s) {
  const std::string::size_type p1 = s.find('[');
  if (p1 == std::string::npos) {
    return s;
  }
  const std::string::size_type p2 = s.find(']', p1);
  if (p2 == std::string::npos) {
    return s;
  }
  return s.substr(p1 + 1, p2 - p1 - 1);
}

static std::unordered_map<std::string, NetInfo>
read_net(const std::string& path,
         const net_type type) {
  std::ifstream f(path);
  std::unordered_map<std::string, NetInfo> out;
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
    const std::string hex_local = fields[1];
    const std::string hex_remote = fields[2];
    const std::string hex_st = fields[3];
    const std::string inode = fields[9];
    out[inode] = NetInfo(type, inode, hex_local, hex_remote, hex_st);
  }
  return out;
}
static std::unordered_map<std::string, NetInfo>
read_tcp(const std::string& pid) {
  return read_net("/proc/" + pid + "/net/tcp", N_TCP);
}
static std::unordered_map<std::string, NetInfo>
read_udp(const std::string& pid) {
  return read_net("/proc/" + pid + "/net/udp", N_UDP);
}
static std::unordered_map<std::string, NetInfo>
read_tcp6(const std::string& pid) {
  return read_net("/proc/" + pid + "/net/tcp6", N_TCP6);
}
static std::unordered_map<std::string, NetInfo>
read_udp6(const std::string& pid) {
  return read_net("/proc/" + pid + "/net/udp6", N_UDP6);
}
static std::unordered_map<std::string, NetInfo>
read_unix(const std::string& pid) {
  std::ifstream f("/proc/" + pid + "/net/unix");
  std::unordered_map<std::string, NetInfo> out;
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
    const std::string hex_type = fields[4];
    const std::string hex_st   = fields[5];
    const std::string inode = fields[6];
    const std::string raw_path =
      (fields.size() > 7) ? fields[7] : "";
    out[inode] = NetInfo(N_UNIX, inode, raw_path, hex_type, hex_st);
  }
  return out;
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
        std::string events;
        iss >> events;
        fd_info.set(tfd, events);
      }
      continue;
    }
    if (t == "ino:") {
      iss >> inode;
    }
  }
  return NetInfo(N_EPOLL, inode, fd_info);
}

// ----------------------------------------------------------------------

struct Snapshot {
  std::map<int, Info> fd_info_map;
  void snapshot(const std::string& pid) {
    fd_info_map.clear();
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
        const std::string inode = get_inode(target);
        bool b = false;
        b = update_fd_info_map_(n_fd, inode, inode_tcp_map);
        if (b) {
          continue;
        }
        b = update_fd_info_map_(n_fd, inode, inode_udp_map);
        if (b) {
          continue;
        }
        b = update_fd_info_map_(n_fd, inode, inode_tcp6_map);
        if (b) {
          continue;
        }
        b = update_fd_info_map_(n_fd, inode, inode_udp6_map);
        if (b) {
          continue;
        }
        b = update_fd_info_map_(n_fd, inode, inode_unix_map);
        if (b) {
          continue;
        }
        fd_info_map.insert({n_fd,
            Info(NetInfo(N_UNKNOWN, inode, target))});
      } else if (target.find("anon_inode:[eventpoll]") == 0) {
        fd_info_map.insert({n_fd, Info(read_fdinfo(pid, fd))});
      } else {
        fd_info_map.insert({n_fd, Info(target)});
      }
    }
    closedir(d);
  }
  bool update_fd_info_map_(
      int fd, const std::string& inode,
      const std::unordered_map<std::string, NetInfo>& inode_net_map) {
    auto iter = inode_net_map.find(inode);
    if (iter == inode_net_map.end()) {
      return false;
    }
    const NetInfo& net_info = iter->second;
    fd_info_map[fd] = Info(net_info);
    return true;
  }

  Difference update_to(const Snapshot& new_snap,
                       timestamp_t timestamp) {
    Difference diff(timestamp);
    std::list<int> deleted_fds;
    for (const auto& v : fd_info_map) {
      const int fd = v.first;
      const Info& old_info = v.second;
      auto it = new_snap.fd_info_map.find(fd);
      if (it == new_snap.fd_info_map.end()) {
        diff.act_delete(fd, old_info);
        deleted_fds.push_back(fd);
      }
    }
    for (int fd : deleted_fds) {
      fd_info_map.erase(fd);
    }
    for (const auto& v : new_snap.fd_info_map) {
      const int fd = v.first;
      const Info& new_info = v.second;
      auto it = fd_info_map.find(fd);
      if (it == fd_info_map.end()) {
        fd_info_map.insert({fd, new_info});
        diff.act_new(fd, new_info);
      } else {
        Info& old_info = it->second;
        if (new_info == old_info) {
          continue;  // not changed
        }
        diff.act_update(fd, old_info, new_info);
        old_info = new_info;
      }
    }
    return diff;
  }
};

int
main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "usage: " << argv[0] << " PID\n";
    return 1;
  }
  const std::string pid = argv[1];
  try {
    Snapshot summary_snapshot;
    for (;;) {
      Snapshot current_snapshot;
      current_snapshot.snapshot(pid);
      const timestamp_t timestamp = std::chrono::system_clock::now();
      auto difference = summary_snapshot.update_to(current_snapshot, timestamp);
      difference.report();
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << std::endl;
  } catch (...) {
    std::cerr << "unknown exception" << std::endl;
  }
}
