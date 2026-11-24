// Fuzz every core_sim topic/response message unpacker (the bodies the
// TopicManager receive loop hands to MessageUtils::ToMessage / that clients
// publish). Byte 0 selects the message class, the rest is the msgpack body.
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>

#include "core_sim/message/airspeed_message.hpp"
#include "core_sim/message/barometer_message.hpp"
#include "core_sim/message/battery_message.hpp"
#include "core_sim/message/camera_info_message.hpp"
#include "core_sim/message/clock_message.hpp"
#include "core_sim/message/collision_info_message.hpp"
#include "core_sim/message/distance_sensor_message.hpp"
#include "core_sim/message/flight_control_rc_input_message.hpp"
#include "core_sim/message/flight_control_setpoint_message.hpp"
#include "core_sim/message/float_message.hpp"
#include "core_sim/message/gps_message.hpp"
#include "core_sim/message/image_message.hpp"
#include "core_sim/message/imu_message.hpp"
#include "core_sim/message/int8_message.hpp"
#include "core_sim/message/int_list_message.hpp"
#include "core_sim/message/joint_state_message.hpp"
#include "core_sim/message/kinematics_message.hpp"
#include "core_sim/message/lidar_message.hpp"
#include "core_sim/message/magnetometer_message.hpp"
#include "core_sim/message/physics_state_message.hpp"
#include "core_sim/message/pose_message.hpp"
#include "core_sim/message/pose_stamped_message.hpp"
#include "core_sim/message/radar_detection_message.hpp"
#include "core_sim/message/radar_track_message.hpp"
#include "core_sim/message/ready_state_message.hpp"
#include "core_sim/message/response_failure_message.hpp"
#include "core_sim/message/response_success_message.hpp"
#include "core_sim/message/rotor_message.hpp"
#include "core_sim/message/transform_message.hpp"

using namespace microsoft::projectairsim;

template <typename T>
static void Run(const std::string& buf) {
  T msg;
  msg.Deserialize(buf);
  (void)msg.GetType();
  (void)msg.Serialize();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return -1;
  std::string buf(reinterpret_cast<const char*>(data + 1), size - 1);
  try {
    switch (data[0] % 29) {
      case 0: Run<AirspeedMessage>(buf); break;
      case 1: Run<BarometerMessage>(buf); break;
      case 2: Run<BatteryStateMessage>(buf); break;
      case 3: Run<CameraInfoMessage>(buf); break;
      case 4: Run<ClockMessage>(buf); break;
      case 5: Run<CollisionInfoMessage>(buf); break;
      case 6: Run<DistanceSensorMessage>(buf); break;
      case 7: Run<FlightControlRCInputMessage>(buf); break;
      case 8: Run<FlightControlSetpointMessage>(buf); break;
      case 9: Run<FloatMessage>(buf); break;
      case 10: Run<GpsMessage>(buf); break;
      case 11: Run<ImageMessage>(buf); break;
      case 12: Run<ImuMessage>(buf); break;
      case 13: Run<Int8Message>(buf); break;
      case 14: Run<IntListMessage>(buf); break;
      case 15: Run<JointStateMessage>(buf); break;
      case 16: Run<KinematicsMessage>(buf); break;
      case 17: Run<LidarMessage>(buf); break;
      case 18: Run<MagnetometerMessage>(buf); break;
      case 19: Run<PhysicsStateMessage>(buf); break;
      case 20: Run<PoseMessage>(buf); break;
      case 21: Run<PoseStampedMessage>(buf); break;
      case 22: Run<RadarDetectionMessage>(buf); break;
      case 23: Run<RadarTrackMessage>(buf); break;
      case 24: Run<ReadyStateMessage>(buf); break;
      case 25: Run<ResponseFailureMessage>(buf); break;
      case 26: Run<ResponseSuccessMessage>(buf); break;
      case 27: Run<RotorMessage>(buf); break;
      case 28: Run<TransformMessage>(buf); break;
    }
  } catch (const std::exception&) {
    // msgpack/json type errors are the library's rejection path.
  }
  return 0;
}
