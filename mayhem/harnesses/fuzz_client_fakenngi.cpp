// Fuzz the C++ client library (client/cpp/ProjectAirsimClientLib) end to end over
// upstream's own FakeNNGI transport mock (client/cpp/tests/FakeNNGI.cpp), the same
// "ProjectAirsimClientMocked" build that upstream's CppClientUnitTests use.
//
// The fuzz bytes are the sim server's replies on the request/response socket. Each input
// issues a fixed series of client API calls; each call's request goes through the client's
// request-sending thread, its reply is read by the response-receiving thread and handed
// back through TAsyncResultProvider / AsyncResultInternal (the code fixed by 7b1134bb),
// and the API then parses it (ResponseMessage::Deserialize + the JSON result accessors).
//
// State kept across inputs, on purpose: one connected asc::Client (Connect spawns three
// threads, and Disconnect waits up to 0.5 s for them, so per-input reconnects would cap
// throughput at ~2 exec/s). Every call below is waited on synchronously, so no request,
// reply or async result outlives its input; the fake transport's queues are cleared with
// fake_nngi::Reset() before each input. The only value carried over is the client's
// request-id counter, which the client never compares with a reply. The topic socket
// gets no frames (FakeNNGI reports a timeout), so the topic thread stays idle.
#include <fuzzer/FuzzedDataProvider.h>
#include <stdint.h>

#include <exception>
#include <string>
#include <vector>

#include <ProjectAirsimClient/ProjectAirsimClient.h>
#include <ProjectAirSimMessage/response_message.hpp>

#include "FakeNNGI.h"

namespace asc = microsoft::projectairsim::client;
namespace pas = microsoft::projectairsim;
namespace fake_nngi = projectairsim_cpp_tests::fake_nngi;
using json = nlohmann::json;

namespace {
asc::Client* g_client = nullptr;

// The way the client's own API methods consume a reply (Client::Impl::GetBuildCommitHash).
void ParseReply(const asc::Message& message) {
  pas::ResponseMessage rm;
  rm.Deserialize(message);
  if (rm.GetErrorCode() == 0) {
    json result = rm.GetResult();
    (void)result.dump();
  } else {
    (void)static_cast<std::string>(rm.GetResult()["message"]);
  }
}
}  // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fake_nngi::Reset();
  g_client = new asc::Client();
  if (g_client->Connect("127.0.0.1") != asc::Status::OK) abort();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  fake_nngi::Reset();

  // Up to 6 server replies, one per call below; calls past the last reply see the
  // transport's "canceled" error, like a dropped connection.
  std::vector<std::string> replies;
  while (replies.size() < 6 && fdp.remaining_bytes() > 0)
    replies.push_back(fdp.ConsumeRandomLengthString(fdp.remaining_bytes()));
  for (const auto& r : replies) fake_nngi::PushServiceResponse(r);

  try {
    asc::Message response;
    if (g_client->Request("/Sim/GetSceneConfig", json::object(), &response) ==
        asc::Status::OK)
      ParseReply(response);
  } catch (const std::exception&) {
  }

  try {
    std::string hash;
    (void)g_client->GetBuildCommitHash(&hash);
  } catch (const std::exception&) {
  }

  try {
    bool enabled = false;
    (void)g_client->SetInteractiveFeature("fuzz", true, &enabled);
  } catch (const std::exception&) {
  }

  // Two requests in flight at once, completed in order by the receiving thread.
  try {
    auto ar1 = g_client->RequestAsync("/Sim/GetSimTime", json::object());
    auto ar2 = g_client->RequestAsync("/Sim/Unit", json{{"name", "Drone1"}});
    if (ar1.Wait() == asc::Status::OK) ParseReply(ar1.GetResult());
    if (ar2.Wait() == asc::Status::OK) ParseReply(ar2.GetResult());
  } catch (const std::exception&) {
  }

  try {
    asc::Message response;
    if (g_client->Request("/Sim/GetSimClockType", json::object(), &response) ==
        asc::Status::OK)
      ParseReply(response);
  } catch (const std::exception&) {
  }
  return 0;
}
