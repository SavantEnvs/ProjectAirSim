// Fuzz the client's JSONC config loader: LoadJSONCFromFile (the jsoncbuf
// comment-stripping streambuf feeding nlohmann::json), used for every
// scene/robot .jsonc config the client reads.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>

#include "jsonc.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const char* tmpdir = getenv("TMPDIR");
  std::string path = std::string(tmpdir && *tmpdir ? tmpdir : "/tmp") +
                     "/fuzz_jsonc_XXXXXX";
  int fd = mkstemp(&path[0]);
  if (fd < 0) return 0;
  size_t off = 0;
  while (off < size) {
    ssize_t n = write(fd, data + off, size - off);
    if (n <= 0) break;
    off += n;
  }
  close(fd);
  nlohmann::json j;
  microsoft::projectairsim::client::LoadJSONCFromFile(path, &j);
  (void)j.dump();
  unlink(path.c_str());
  return 0;
}
