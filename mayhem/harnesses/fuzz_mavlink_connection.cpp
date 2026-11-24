// Fuzz the mavlinkcom connection receive path: MavLinkConnection::startListening
// over an in-memory Port that serves the fuzz bytes as the remote's stream.
// Covers the read thread's MAVLink v1/v2 framing (mavlink_frame_char_buffer,
// CRC, signing), the publish thread's dispatch to subscribers, and typed decode
// (MavLinkMessageBase::lookup -> decode -> toJSon) of each framed message.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

#include "MavLinkConnection.hpp"
#include "MavLinkMessages.hpp"
#include "Port.h"

using namespace mavlinkcom;

namespace {
// A Port whose remote end sent exactly the fuzz input and then went silent.
class MemoryPort : public Port {
 public:
  MemoryPort(const uint8_t* data, size_t size) : buf_(data, data + size) {}
  int write(const uint8_t*, int count) override { return count; }
  int read(uint8_t* buffer, int bytesToRead) override {
    size_t left = buf_.size() - pos_;
    if (left == 0) {
      // readPackets() only calls read() again after framing every byte of the
      // previous chunk, so this marks the whole input as parsed and queued.
      drained_ = true;
      return 0;
    }
    size_t n = left < static_cast<size_t>(bytesToRead) ? left : bytesToRead;
    memcpy(buffer, buf_.data() + pos_, n);
    pos_ += n;
    return static_cast<int>(n);
  }
  void close() override { closed_ = true; }
  bool isClosed() override { return closed_; }
  int getRssi(const char*) override { return 0; }
  std::atomic<bool> drained_{false};

 private:
  std::vector<uint8_t> buf_;
  size_t pos_ = 0;
  std::atomic<bool> closed_{false};
};

// startListening(name, Port) is the protected hook the library's own transports
// (connectSerial/connectLocalUdp/connectTcp/acceptTcp) use to attach a Port;
// expose it so the stream comes from memory instead of a socket.
class FuzzConnection : public MavLinkConnection {
 public:
  using MavLinkConnection::startListening;
};
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  auto port = std::make_shared<MemoryPort>(data, size);
  auto con = std::make_shared<FuzzConnection>();
  std::atomic<uint64_t> handled{0};
  con->subscribe([&handled](std::shared_ptr<MavLinkConnection>,
                            const MavLinkMessage& msg) {
    MavLinkMessageBase* m = MavLinkMessageBase::lookup(msg);
    if (m != nullptr) {
      (void)m->toJSon();
      delete m;
    }
    handled++;
  });
  con->startListening("fuzz", port);
  while (!port->drained_) std::this_thread::yield();
  MavLinkTelemetry tele;
  con->getTelemetry(tele);
  // Every framed message has been queued; wait until the publish thread has
  // handed each one to the subscriber, so the result depends only on the input.
  while (handled < tele.messages_received) std::this_thread::yield();
  con->close();
  return 0;
}
