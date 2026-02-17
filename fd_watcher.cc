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
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

enum class info_type {
  I_UNKNOWN,
  I_UDP,
  I_TCP,
  I_UDP6,
  I_TCP6,
  I_UNIX,
  I_PIPE,
  I_EPOLL,
  I_FILE,
};
static const char*
info_type_str(info_type itype) {
  switch (itype) {
  case info_type::I_UDP: return "UDP";
  case info_type::I_TCP: return "TCP";
  case info_type::I_UDP6: return "UDP6";
  case info_type::I_TCP6: return "TCP6";
  case info_type::I_UNIX: return "UNIX";
  case info_type::I_EPOLL: return "EPOLL";
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
  using ptr = std::shared_ptr<FdInfo>;
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

struct Info {
  using ptr = std::shared_ptr<Info>;
  info_type itype;
  Info(info_type itype) : itype(itype) {
  }
  virtual ~Info() = default;
  virtual bool equals(const Info& other) const = 0;
  virtual void print_to(std::ostream& stream) const = 0;
};

struct UnknownInfo : public Info {
  using ptr = std::shared_ptr<UnknownInfo>;
  std::string inode;
  std::string raw;
  UnknownInfo(const std::string& inode,
              const std::string& raw)
    : Info(info_type::I_UNKNOWN), inode(inode), raw(raw) {
  }
  ~UnknownInfo() {
  }
  bool equals(const Info& other) const override {
    const UnknownInfo* p = dynamic_cast<const UnknownInfo*>(&other);
    if (!p) {
      return false;
    }
    return inode == p->inode &&
      raw == p->raw;
  }
  void print_to(std::ostream& stream) const override {
    stream << "{"
      "\"type\":\"" << info_type_str(itype) << "\""
      ",\"inode\":\"" << inode << "\""
      ",\"raw\":\"" << jstr(raw) << "\""
      "}";
  }
};

struct TcpUdpInfo : public Info {
  using ptr = std::shared_ptr<TcpUdpInfo>;
  std::string inode;
  std::string local;
  std::string remote;
  std::string st;
  TcpUdpInfo(info_type itype,
             const std::string& inode,
             const std::string& local,
             const std::string& remote,
             const std::string& st)
    : Info(itype), inode(inode), local(local), remote(remote), st(st) {
  }
  ~TcpUdpInfo() {
  }
  bool equals(const Info& other) const override {
    const TcpUdpInfo* p = dynamic_cast<const TcpUdpInfo*>(&other);
    if (!p) {
      return false;
    }
    return itype == p->itype &&
      inode == p->inode &&
      local == p->local &&
      remote == p->remote &&
      st == p->st;
  }
  void print_to(std::ostream& stream) const override {
    stream << "{"
      "\"type\":\"" << info_type_str(itype) << "\""
      ",\"inode\":\"" << inode << "\""
      ",\"local\":\"" << local << "\""
      ",\"remote\":\"" << remote << "\""
      ",\"st\":\"" << st << "\""
      "}";
  }
};

struct UnixInfo : public Info {
  using ptr = std::shared_ptr<UnixInfo>;
  std::string inode;
  std::string path;
  std::string stype;
  std::string st;
  UnixInfo(const std::string& inode,
           const std::string& path,
           const std::string& stype,
           const std::string& st)
    : Info(info_type::I_UNIX),
      inode(inode), path(path), stype(stype), st(st) {
  }
  ~UnixInfo() {
  }
  bool equals(const Info& other) const override {
    const UnixInfo* p = dynamic_cast<const UnixInfo*>(&other);
    if (!p) {
      return false;
    }
    return
      inode == p->inode &&
      path == p->path &&
      stype == p->stype &&
      st == p->st;
  }
  void print_to(std::ostream& stream) const override {
    stream << "{"
      "\"type\":\"" << info_type_str(itype) << "\""
      ",\"inode\":\"" << inode << "\""
      ",\"path\":\"" << jstr(path) << "\""
      ",\"stype\":\"" << stype << "\""
      ",\"st\":\"" << st << "\""
      "}";
  }
};

struct PipeInfo : public Info {
  using ptr = std::shared_ptr<PipeInfo>;
  std::string inode;
  PipeInfo(const std::string& inode)
    : Info(info_type::I_PIPE), inode(inode) {
  }
  ~PipeInfo() {
  }
  bool equals(const Info& other) const override {
    const PipeInfo* p = dynamic_cast<const PipeInfo*>(&other);
    if (!p) {
      return false;
    }
    return inode == p->inode;
  }
  void print_to(std::ostream& stream) const override {
    stream << "{"
      "\"type\":\"" << info_type_str(itype) << "\""
      ",\"inode\":\"" << inode << "\""
      "}";
  }
};

struct EpollInfo : public Info {
  using ptr = std::shared_ptr<EpollInfo>;
  std::string inode;
  FdInfo::ptr fd_info;
  EpollInfo(const std::string& inode, FdInfo::ptr fd_info)
    : Info(info_type::I_EPOLL), inode(inode), fd_info(fd_info) {
  }
  ~EpollInfo() {
  }
  bool equals(const Info& other) const override {
    const EpollInfo* p = dynamic_cast<const EpollInfo*>(&other);
    if (!p) {
      return false;
    }
    return inode == p->inode &&
      *fd_info == *p->fd_info;
  }
  void print_to(std::ostream& stream) const override {
    stream << "{"
      "\"type\":\"" << info_type_str(itype) << "\""
      ",\"inode\":\"" << inode << "\""
      ",\"events\":" << *fd_info <<
      "}";
  }
};

struct FileInfo : public Info {
  using ptr = std::shared_ptr<FileInfo>;
  std::string target;
  FileInfo(const std::string& target)
    : Info(info_type::I_FILE), target(target) {
  }
  ~FileInfo() {
  }
  bool equals(const Info& other) const override {
    const FileInfo* p = dynamic_cast<const FileInfo*>(&other);
    if (!p) {
      return false;
    }
    return target == p->target;
  }
  void print_to(std::ostream& stream) const override {
    stream << "{"
      "\"type\":\"" << info_type_str(itype) << "\""
      ",\"target\":\"" << jstr(target) << "\""
      "}";
  }
};

std::ostream& operator<<(std::ostream& stream,
                         const Info::ptr& info) {
  info->print_to(stream);
  return stream;
}

// ----------------------------------------------------------------------

enum class action_type {
  A_NONE,
  A_NEW,
  A_UPDATE,
  A_DELETE,
};

static std::string
action_str(action_type atype) {
  switch (atype) {
  case action_type::A_NEW: return "NEW";
  case action_type::A_UPDATE: return "UPDATE";
  case action_type::A_DELETE: return "DELETE";
  default: return "?";
  }
}

struct Action {
  action_type atype;
  Info::ptr old_info;
  Info::ptr new_info;
  Action() : atype(action_type::A_NONE) {
  }
  Action(action_type atype, Info::ptr old_info, Info::ptr new_info)
    : atype(atype), old_info(old_info), new_info(new_info) {
  }
};

struct Difference {
  timestamp_t timestamp;
  std::map<int, Action> change_fd_action_map;
  explicit Difference(timestamp_t timestamp)
    : timestamp(timestamp) {
  }
  void act_new(int fd, Info::ptr info) {
    change_fd_action_map.insert({fd,
        Action(action_type::A_NEW, nullptr, info)});
  }
  void act_update(int fd, Info::ptr old_info, Info::ptr new_info) {
    change_fd_action_map.insert({fd,
        Action(action_type::A_UPDATE, old_info, new_info)});
  }
  void act_delete(int fd, Info::ptr info) {
    change_fd_action_map.insert({fd,
        Action(action_type::A_DELETE, info, nullptr)});
  }
  void report() const {
    for (const auto& v : change_fd_action_map) {
      const int fd = v.first;
      const Action& action = v.second;
      std::cout << "{"
        "\"timestamp\":\"" << timestamp_str(timestamp) << "\""
        ",\"fd\":\"" << fd << "\""
        ",\"updateType\":\"" << action_str(action.atype) << "\"";
      if (action.new_info) {
        std::cout <<
          ",\"new\":" << action.new_info;
      }
      if (action.old_info) {
        std::cout <<
          ",\"old\":" << action.old_info;
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

static void
append_net_info(const info_type itype,
                const std::string& path,
                std::unordered_map<std::string, Info::ptr>* inode_info_map) {
  std::ifstream f(path);
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
    (*inode_info_map)[inode] =
      std::make_shared<TcpUdpInfo>(itype, inode, hex_local, hex_remote, hex_st);
  }
}
static void
append_tcp_info(const std::string& pid,
                std::unordered_map<std::string, Info::ptr>* inode_info_map) {
  append_net_info(info_type::I_TCP,
                  "/proc/" + pid + "/net/tcp",
                  inode_info_map);
}
static void
append_udp_info(const std::string& pid,
                std::unordered_map<std::string, Info::ptr>* inode_info_map) {
  append_net_info(info_type::I_UDP,
                  "/proc/" + pid + "/net/udp",
                  inode_info_map);
}
static void
append_tcp6_info(const std::string& pid,
                 std::unordered_map<std::string, Info::ptr>* inode_info_map) {
  append_net_info(info_type::I_TCP6,
                  "/proc/" + pid + "/net/tcp6",
                  inode_info_map);
}
static void
append_udp6_info(const std::string& pid,
                 std::unordered_map<std::string, Info::ptr>* inode_info_map) {
  append_net_info(info_type::I_UDP6,
                  "/proc/" + pid + "/net/udp6",
                  inode_info_map);
}
static void
append_unix_info(const std::string& pid,
                 std::unordered_map<std::string, Info::ptr>* inode_info_map) {
  std::ifstream f("/proc/" + pid + "/net/unix");
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
    (*inode_info_map)[inode] =
      std::make_shared<UnixInfo>(inode, raw_path, hex_type, hex_st);
  }
}
static EpollInfo::ptr
read_fdinfo(const std::string& pid, const std::string& fd) {
  std::string inode;
  FdInfo::ptr fd_info = std::make_shared<FdInfo>();
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
        fd_info->set(tfd, events);
      }
      continue;
    }
    if (t == "ino:") {
      iss >> inode;
    }
  }
  return std::make_shared<EpollInfo>(inode, fd_info);
}

// ----------------------------------------------------------------------

struct Snapshot {
  std::map<int, Info::ptr> fd_info_map;
  void snapshot(const std::string& pid) {
    fd_info_map.clear();
    std::unordered_map<std::string, Info::ptr> inode_info_map;
    append_udp_info(pid, &inode_info_map);
    append_tcp_info(pid, &inode_info_map);
    append_udp6_info(pid, &inode_info_map);
    append_tcp6_info(pid, &inode_info_map);
    append_unix_info(pid, &inode_info_map);
    DIR* d = opendir(("/proc/" + pid + "/fd").c_str());
    if (!d) {
      throw std::runtime_error("[cannot open fd directory]");
    }
    struct dirent* e;
    char buf[4096];

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
        bool b = update_fd_info_map_(n_fd, inode, inode_info_map);
        if (b) {
          continue;
        }
        fd_info_map.insert({n_fd,
            std::make_shared<UnknownInfo>(inode, target)});
      } else if (target.find("pipe:[") == 0) {
        const std::string inode = get_inode(target);
        fd_info_map.insert({n_fd,
            std::make_shared<PipeInfo>(inode)});
      } else if (target.find("anon_inode:[eventpoll]") == 0) {
        fd_info_map.insert({n_fd, read_fdinfo(pid, fd)});
      } else {
        fd_info_map.insert({n_fd, std::make_shared<FileInfo>(target)});
      }
    }
    closedir(d);
  }
  bool update_fd_info_map_(
      int fd, const std::string& inode,
      const std::unordered_map<std::string, Info::ptr>& inode_info_map) {
    auto iter = inode_info_map.find(inode);
    if (iter == inode_info_map.end()) {
      return false;
    }
    fd_info_map[fd] = iter->second;
    return true;
  }

  Difference update_to(const Snapshot& new_snap,
                       timestamp_t timestamp) {
    Difference diff(timestamp);
    std::vector<int> deleted_fds;
    deleted_fds.reserve(fd_info_map.size());
    for (const auto& v : fd_info_map) {
      const int fd = v.first;
      const Info::ptr& old_info = v.second;
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
      const Info::ptr& new_info = v.second;
      auto it = fd_info_map.find(fd);
      if (it == fd_info_map.end()) {
        fd_info_map.insert({fd, new_info});
        diff.act_new(fd, new_info);
      } else {
        Info::ptr& old_info = it->second;
        if (old_info->equals(*new_info)) {
          continue;  // not changed
        }
        diff.act_update(fd, old_info, new_info);
        it->second = new_info;
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
