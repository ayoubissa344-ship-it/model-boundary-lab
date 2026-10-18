#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// ModelBoundary Lab native observation probe. It observes; it does not create a sandbox.
struct Check { std::string name; std::string status; std::string detail; };
static std::string readlink_text(const std::string& p) {
  char buf[256]{}; auto n = ::readlink(p.c_str(), buf, sizeof(buf)-1);
  if (n < 0) return std::string("unavailable:") + std::strerror(errno);
  return std::string(buf, static_cast<size_t>(n));
}
static std::string trim(std::string s) {
  while (!s.empty() && (s.back()=='\n'||s.back()=='\r'||s.back()==' ')) s.pop_back();
  return s;
}
static std::string read_file(const std::string& p) {
  std::ifstream f(p); if (!f) return "unavailable";
  std::ostringstream ss; ss << f.rdbuf(); return trim(ss.str());
}
static void emit(const Check& c, bool json) {
  if (!json) { std::cout << c.name << ": " << c.status << " - " << c.detail << "\n"; return; }
  auto esc=[](const std::string& s){
    std::string o;
    for (unsigned char c : s) {
      switch (c) {
        case '\"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
          if (c < 0x20) {
            const char hex[] = "0123456789abcdef";
            o += "\\u00"; o += hex[(c >> 4) & 0xf]; o += hex[c & 0xf];
          } else o += static_cast<char>(c);
      }
    }
    return o;
  };
  std::cout << "{\"name\":\""<<esc(c.name)<<"\",\"status\":\""<<esc(c.status)<<"\",\"detail\":\""<<esc(c.detail)<<"\"}\n";
}
int main(int argc, char** argv) {
  bool json=false; for(int i=1;i<argc;i++) if(std::string(argv[i])=="--jsonl") json=true;
  std::vector<Check> out;
  for (const auto& ns : {"user","mnt","net","ipc","uts","pid","cgroup","time"}) {
    std::string p = std::string("/proc/self/ns/")+ns;
    auto v=readlink_text(p);
    out.push_back({std::string("namespace.")+ns, v.rfind("unavailable:",0)==0?"INCONCLUSIVE":"OBSERVED",v});
  }
  out.push_back({"process.no_new_privs", "OBSERVED", read_file("/proc/self/status").find("NoNewPrivs:\t1")!=std::string::npos ? "NoNewPrivs=1" : "NoNewPrivs not confirmed"});
  auto caps=read_file("/proc/self/status");
  auto pos=caps.find("CapEff:");
  out.push_back({"process.effective_capabilities",pos==std::string::npos?"INCONCLUSIVE":"OBSERVED",pos==std::string::npos?"CapEff unavailable":trim(caps.substr(pos,32))});
  for(const auto& c:out) emit(c,json);
  size_t bad=0; for(const auto& c:out) if(c.status=="INCONCLUSIVE") ++bad;
  return bad ? 2 : 0;
}
