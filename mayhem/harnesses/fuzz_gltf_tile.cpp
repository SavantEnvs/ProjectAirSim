// Fuzz the GLB tile reader: GLTFDataProvider::GetTileMeshData (rendering/scene).
// The provider asks its FileReaderInterface for "<quadkey>.glb"; here the reader
// returns the fuzz input, so tinygltf's LoadBinaryFromMemory and the provider's
// FillVertexData/FillUVData/FillIndices/FillTextureData run on it, exactly as for a
// tile file read from disk. Exceptions are the provider's documented error path.
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>

#include "gltf_data_provider.hpp"

namespace scene = microsoft::projectairsim::rendering::scene;

namespace {
class FuzzFileReader : public scene::FileReaderInterface {
 public:
  explicit FuzzFileReader(std::string bytes) : bytes_(std::move(bytes)) {}
  std::string ReadFile(const std::string&) const override { return bytes_; }

 private:
  std::string bytes_;
};
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  scene::GLTFDataProvider provider(std::make_unique<FuzzFileReader>(
      std::string(reinterpret_cast<const char*>(data), size)));
  try {
    scene::MeshData mesh = provider.GetTileMeshData(scene::TileKey(1, 2, 3));
    volatile size_t n = mesh.vertices.size() + mesh.uvs.size() +
                        mesh.triangle_indices.size() + mesh.texture.buffer.size();
    (void)n;
  } catch (const std::exception&) {
  }
  return 0;
}
