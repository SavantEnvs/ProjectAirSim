// Fuzz the C++ client's parse of server replies:
// client::ResponseMessage::Deserialize (success/failure discrimination and
// the result/error JSON), as the client runs on every request-reply.
#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>

#include "response_message.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string buf(reinterpret_cast<const char*>(data), size);
  try {
    microsoft::projectairsim::ResponseMessage msg;
    msg.Deserialize(buf);
    (void)msg.GetID();
    (void)msg.GetErrorCode();
    (void)msg.GetResult().dump();
    (void)msg.GetVersion();
  } catch (const std::exception&) {
  }
  return 0;
}
