// Fuzz the core_sim service-request wire parser: RequestMessage::Deserialize
// (msgpack-wrapped JSON, the ServiceManager default) and
// RequestMessage::DeserializeFromJsonStr (the pure-JSON serialization mode),
// exactly what the server runs on every nng request it receives.
#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>

#include "core_sim/message/request_message.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return -1;
  const bool json_mode = data[0] & 1;
  std::string buf(reinterpret_cast<const char*>(data + 1), size - 1);
  try {
    microsoft::projectairsim::RequestMessage msg;
    if (json_mode)
      msg.DeserializeFromJsonStr(buf);
    else
      msg.Deserialize(buf);
    (void)msg.GetID();
    (void)msg.GetMethod();
    auto params = msg.GetParams();
    (void)params.dump();
    (void)msg.GetVersion();
    (void)msg.Serialize();
  } catch (const std::exception&) {
    // ServiceManager wraps deserialization in catch(...): exceptions are the
    // documented rejection path, not bugs.
  }
  return 0;
}
