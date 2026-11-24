// Fuzz the mavlinkcom .mavlink log reader (MavLinkFileLog::read) and the
// typed decode of every generated message (MavLinkMessageBase::lookup ->
// decode -> toJSon), i.e. what replaying an untrusted MAVLink log does.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <string>
#include <unistd.h>

#include "MavLinkLog.hpp"
#include "MavLinkMessages.hpp"

using namespace mavlinkcom;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const char* tmpdir = getenv("TMPDIR");
  std::string path = std::string(tmpdir && *tmpdir ? tmpdir : "/tmp") +
                     "/fuzz_mavlog_XXXXXX";
  int fd = mkstemp(&path[0]);
  if (fd < 0) return 0;
  size_t off = 0;
  while (off < size) {
    ssize_t n = write(fd, data + off, size - off);
    if (n <= 0) break;
    off += n;
  }
  close(fd);
  try {
    MavLinkFileLog log;
    log.openForReading(path);
    MavLinkMessage msg;
    uint64_t ts = 0;
    while (log.read(msg, ts)) {
      MavLinkMessageBase* m = MavLinkMessageBase::lookup(msg);
      if (m != nullptr) {
        (void)m->toJSon();
        delete m;
      }
    }
    log.close();
  } catch (const std::exception&) {
  }
  unlink(path.c_str());
  return 0;
}
