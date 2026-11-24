#!/usr/bin/env bash
#
# mayhem/build.sh — build ProjectAirSim's fuzz harnesses and the message unit tests.
#
# Upstream's top-level CMake hard-codes clang-13/libc++ and downloads ~12 dependencies
# (JSBSim, nng, assimp, onnxruntime-gpu, OpenSSL, ...) at configure time. The harnessed
# code (core_sim message (de)serializers, the C++ client message lib, mavlinkcom) only
# needs the header-only json/msgpack/Eigen dependencies, which come from pinned Debian
# packages (nlohmann-json3-dev, libmsgpack-cxx-dev, libeigen3-dev, libgtest-dev). So this
# script compiles those upstream sources directly, with $SANITIZER_FLAGS for the fuzzers
# and normal flags for the test runner. Everything is written under mayhem/out/
# (gitignored); the script rebuilds from scratch every run, offline.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"
OUT="$SRC/mayhem/out"
rm -rf "$OUT"
mkdir -p "$OUT"

COMMON_DEFS="-std=c++17 -DMSGPACK_NO_BOOST -I/usr/include/nlohmann -I/usr/include/eigen3"
CORE_INC="-I$SRC/core_sim/include -I$SRC/core_sim/src"
CLIENT_INC="-I$SRC/client/cpp/ProjectAirSimMessageLib/include/ProjectAirSimMessage -I$SRC/client/cpp/ProjectAirSimMessageLib -I$SRC/core_sim/include -I$SRC/core_sim/src -I$SRC"
MAV_INC="-I$SRC/mavlinkcom/include -I$SRC/mavlinkcom/src -I$SRC/mavlinkcom -I$SRC/mavlinkcom/common_utils -I$SRC/mavlinkcom/mavlink -I$SRC/mavlinkcom/src/serial_com -I$SRC/mavlinkcom/src/impl"

# core_sim message library sources (core_sim/src/CMakeLists.txt). message_utils.cpp is left out:
# it needs Topic, whose component/topic_manager headers pull in nng sockets.
CORE_SRCS=$(ls core_sim/src/message/*.cpp | grep -v -e width_height_message.cpp -e message_utils.cpp)
CORE_SRCS="$CORE_SRCS core_sim/src/json_utils.cpp core_sim/src/math_utils.cpp core_sim/src/string_utils.cpp core_sim/src/logger.cpp core_sim/src/geodetic_converter.cpp core_sim/src/transforms/transform_utils.cpp core_sim/src/clock.cpp"
CLIENT_SRCS=$(ls client/cpp/ProjectAirSimMessageLib/src/*.cpp)
# GLB tile reader (rendering/scene): gltf_data_provider.cpp defines TINYGLTF_IMPLEMENTATION, so
# tinygltf + stb_image are compiled into it from the cached header-only dep.
TINYGLTF_INC="/opt/toolchains/deps/tinygltf-2.6.3/include"
SCENE_INC="-I$SRC/rendering/scene/include -I$SRC/core_sim/include -I$TINYGLTF_INC"
SCENE_SRCS="rendering/scene/src/gltf_data_provider.cpp rendering/scene/src/bing_maps_utils.cpp core_sim/src/math_utils.cpp"
# Sim-server client authorization (OpenSSL from the pinned Debian libssl-dev, uninstrumented).
# client_authorization.cpp #includes client_authorization_linux.cpp.
AUTH_SRCS="core_sim/src/client_authorization.cpp"
# C++ client library over upstream's FakeNNGI transport mock: the source list of upstream's
# ProjectAirsimClientMocked target (client/cpp/CMakeLists.txt) + tests/FakeNNGI.cpp.
MOCK_DEFS="-DPROJECTAIRSIMCLIENT_STATIC -DNNGI_STATIC_LIB -DNNG_STATIC_LIB -DPROJECTAIRSIMCLIENT_LIB_BUILD"
MOCK_INC="$MOCK_DEFS -I$SRC/client/cpp/ProjectAirsimClientLib -I$SRC/client/cpp/ProjectAirsimClientLib/Include/ProjectAirsimClient -I$SRC/client/cpp/ProjectAirsimClientLib/Include -I$SRC/client/cpp/ProjectAirSimMessageLib/include -I$SRC/client/cpp/ProjectAirSimMessageLib/include/ProjectAirSimMessage -I$SRC/client/cpp/NNGI/include -I$SRC/client/cpp/NNGI/include/NNGI -I$SRC/client/cpp/tests -I$SRC -I$SRC/core_sim/include -I$SRC/core_sim/src"
MOCK_SRCS="$(for f in ProjectAirsimClient AsyncResult AsyncResultInternal Client Drone ICommChannel Log Message RefCounted Status Topics Types Utils World WheeledVehicle Rover EnvActor StaticSensorActor; do echo client/cpp/ProjectAirsimClientLib/src/$f.cpp; done) client/cpp/tests/FakeNNGI.cpp"
MAV_SRCS="$(ls mavlinkcom/src/*.cpp mavlinkcom/src/impl/*.cpp mavlinkcom/src/impl/linux/*.cpp mavlinkcom/src/serial_com/*.cpp mavlinkcom/common_utils/*.cpp)"

# compile <outdir> <flags> <srcs...> : compiles in parallel, prints object paths
compile() {
  local dir="$1" flags="$2"; shift 2
  mkdir -p "$dir"
  local pids=() objs=() s o p fail=0
  for s in "$@"; do
    o="$dir/$(echo "$s" | tr '/' '_').o"
    objs+=("$o")
    $CXX $flags -c "$s" -o "$o" &
    pids+=($!)
    if [ "${#pids[@]}" -ge "$MAYHEM_JOBS" ]; then wait "${pids[0]}" || fail=1; pids=("${pids[@]:1}"); fi
  done
  for p in "${pids[@]}"; do wait "$p" || fail=1; done
  [ "$fail" = 0 ] || { echo "compile failed in $dir" >&2; exit 1; }
  echo "${objs[@]}"
}

# SanCov on the project objects too (unconditionally, also with empty SANITIZER_FLAGS), else
# only the harness TU is coverage-instrumented.
COV_FLAGS="-fsanitize=fuzzer-no-link"
FUZZ_FLAGS="$SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -O1 $COMMON_DEFS"
# MAVLink's generated _mav_get_* accessors read fields straight out of the packed payload, so
# every multi-byte field is a misaligned load by design (benign on x86); UBSan's alignment check
# would fire on the first decoded message of every input. Only that check is relaxed, and only
# for the mavlinkcom objects; ASan and the rest of UBSan stay on and halting.
MAV_RELAX="-fno-sanitize=alignment"

# 1) sanitized project objects
CORE_OBJS=$(compile "$OUT/obj-core" "$FUZZ_FLAGS $CORE_INC" $CORE_SRCS)
CLIENT_OBJS=$(compile "$OUT/obj-client" "$FUZZ_FLAGS $CLIENT_INC" $CLIENT_SRCS)
SCENE_OBJS=$(compile "$OUT/obj-scene" "$FUZZ_FLAGS $SCENE_INC" $SCENE_SRCS)
AUTH_OBJS=$(compile "$OUT/obj-auth" "$FUZZ_FLAGS -Wno-deprecated-declarations $CORE_INC" $AUTH_SRCS)
MOCK_OBJS=$(compile "$OUT/obj-mock" "$FUZZ_FLAGS $MOCK_INC" $MOCK_SRCS)
# The client library's message lib (ResponseMessage/RequestMessage) is the same CLIENT_OBJS.
MAV_OBJS=$(compile "$OUT/obj-mav" "$FUZZ_FLAGS $MAV_RELAX $MAV_INC" $MAV_SRCS)

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

# 2) harnesses: fuzzer + standalone reproducer
link_harness() {
  local name="$1" inc="$2" objs="$3" extra="${4:-}"
  $CXX $FUZZ_FLAGS $extra $inc -c "mayhem/harnesses/$name.cpp" -o "$OUT/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$name.o" $objs "$OUT/lsan_off.o" -pthread -o "$OUT/$name"
  $CXX $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$name.o" $objs "$OUT/lsan_off.o" -pthread -o "$OUT/$name-standalone"
}
link_harness fuzz_request_message "$CORE_INC" "$CORE_OBJS"
link_harness fuzz_topic_message "$CORE_INC" "$CORE_OBJS"
link_harness fuzz_client_response "$CLIENT_INC" "$CLIENT_OBJS"
link_harness fuzz_jsonc "$CLIENT_INC" "$CLIENT_OBJS"
link_harness fuzz_mavlink_log "$MAV_INC" "$MAV_OBJS" "$MAV_RELAX"
link_harness fuzz_mavlink_connection "$MAV_INC" "$MAV_OBJS" "$MAV_RELAX"
link_harness fuzz_client_auth "$CORE_INC" "$AUTH_OBJS $CORE_OBJS -lssl -lcrypto" "-Wno-deprecated-declarations"
link_harness fuzz_client_fakenngi "$MOCK_INC" "$MOCK_OBJS $CLIENT_OBJS $OUT/obj-core/core_sim_src_math_utils.cpp.o"
link_harness fuzz_gltf_tile "$SCENE_INC" "$SCENE_OBJS"

# 3) upstream's own core_sim message/json/string unit tests (gtest), NORMAL flags
TEST_FLAGS="-O1 $COVERAGE_FLAGS $COMMON_DEFS $CORE_INC"
TEST_SRCS="core_sim/test/gtest_message.cpp core_sim/test/gtest_image_message.cpp core_sim/test/gtest_kinematics_message.cpp core_sim/test/gtest_pose_message.cpp core_sim/test/gtest_rotor_message.cpp core_sim/test/gtest_clock_message.cpp core_sim/test/gtest_battery_message.cpp core_sim/test/gtest_json_utils.cpp core_sim/test/gtest_string_utils.cpp"
TOBJS=$(compile "$OUT/obj-test" "$TEST_FLAGS" $CORE_SRCS $TEST_SRCS)
$CXX $COVERAGE_FLAGS $TOBJS -lgtest_main -lgtest -pthread -o "$OUT/core_sim_message_tests"

ls -l "$OUT"/fuzz_* "$OUT/core_sim_message_tests"
