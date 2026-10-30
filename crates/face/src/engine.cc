#include "pam-biometrics-face/src/engine.h"
#include "pam-biometrics-face/src/lib.rs.h"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include <dlib/dnn.h>
#include <dlib/image_processing.h>
#include <dlib/image_processing/frontal_face_detector.h>

namespace pam_biometrics {

namespace network {

using namespace dlib;

// The ResNet of dlib_face_recognition_resnet_model_v1.dat, as in the dlib
// example dnn_face_recognition_ex.cpp and in the dlib Python module.
template <template <int, template <typename> class, int, typename> class block,
          int N, template <typename> class BN, typename SUBNET>
using residual = add_prev1<block<N, BN, 1, tag1<SUBNET>>>;

template <template <int, template <typename> class, int, typename> class block,
          int N, template <typename> class BN, typename SUBNET>
using residual_down =
    add_prev2<avg_pool<2, 2, 2, 2, skip1<tag2<block<N, BN, 2, tag1<SUBNET>>>>>>;

template <int N, template <typename> class BN, int stride, typename SUBNET>
using block =
    BN<con<N, 3, 3, 1, 1, relu<BN<con<N, 3, 3, stride, stride, SUBNET>>>>>;

template <int N, typename SUBNET>
using ares = relu<residual<block, N, affine, SUBNET>>;
template <int N, typename SUBNET>
using ares_down = relu<residual_down<block, N, affine, SUBNET>>;

template <typename SUBNET> using alevel0 = ares_down<256, SUBNET>;
template <typename SUBNET>
using alevel1 = ares<256, ares<256, ares_down<256, SUBNET>>>;
template <typename SUBNET>
using alevel2 = ares<128, ares<128, ares_down<128, SUBNET>>>;
template <typename SUBNET>
using alevel3 = ares<64, ares<64, ares<64, ares_down<64, SUBNET>>>>;
template <typename SUBNET> using alevel4 = ares<32, ares<32, ares<32, SUBNET>>>;

using anet_type = loss_metric<fc_no_bias<
    128,
    avg_pool_everything<alevel0<alevel1<alevel2<alevel3<alevel4<max_pool<
        3, 3, 2, 2,
        relu<affine<con<32, 7, 7, 2, 2, input_rgb_image_sized<150>>>>>>>>>>>>>;

} // namespace network

// face_recognition passes 150 to get_face_chip_details and keeps the default
// padding of the dlib Python module.
constexpr unsigned long chip_size = 150;
constexpr double chip_padding = 0.25;
// The batch size of the dlib Python module.
constexpr unsigned long batch_size = 16;

struct Engine::Models {
  dlib::frontal_face_detector detector = dlib::get_frontal_face_detector();
  dlib::shape_predictor predictor;
  network::anet_type net;
};

Engine::Engine() : models(std::make_unique<Models>()) {}

Engine::~Engine() = default;

std::unique_ptr<Engine> new_engine(rust::Str shape_predictor,
                                   rust::Str recognition_model) {
  auto engine = std::make_unique<Engine>();
  dlib::deserialize(std::string(shape_predictor)) >> engine->models->predictor;
  dlib::deserialize(std::string(recognition_model)) >> engine->models->net;
  return engine;
}

rust::Vec<Face> analyze(Engine &engine, rust::Slice<const std::uint8_t> rgb,
                        std::size_t width, std::size_t height) {
  Engine::Models &models = *engine.models;
  if (width == 0 || height == 0 || rgb.size() != width * height * 3)
    throw std::invalid_argument("the frame size does not match its dimensions");

  dlib::matrix<dlib::rgb_pixel> image(static_cast<long>(height),
                                      static_cast<long>(width));
  const std::uint8_t *pixel = rgb.data();
  for (long row = 0; row < image.nr(); ++row) {
    for (long column = 0; column < image.nc(); ++column) {
      image(row, column) = dlib::rgb_pixel(pixel[0], pixel[1], pixel[2]);
      pixel += 3;
    }
  }

  // face_recognition.face_locations(image, number_of_times_to_upsample=0,
  // model="hog") runs the detector without upsampling and trims each box to
  // the image bounds.
  const std::vector<dlib::rectangle> detections = models.detector(image);
  const long columns = static_cast<long>(width);
  const long rows = static_cast<long>(height);

  rust::Vec<Face> faces;
  std::vector<dlib::chip_details> chips;
  for (const dlib::rectangle &detection : detections) {
    Face face;
    face.top = std::max(detection.top(), 0L);
    face.right = std::min(detection.right(), columns);
    face.bottom = std::min(detection.bottom(), rows);
    face.left = std::max(detection.left(), 0L);
    const dlib::rectangle box(face.left, face.top, face.right, face.bottom);
    // face_recognition.face_encodings(model="small") uses the 5-point
    // predictor and compute_face_descriptor with num_jitters=1.
    const dlib::full_object_detection shape = models.predictor(image, box);
    chips.push_back(
        dlib::get_face_chip_details(shape, chip_size, chip_padding));
    faces.push_back(std::move(face));
  }
  if (faces.empty())
    return faces;

  dlib::array<dlib::matrix<dlib::rgb_pixel>> face_chips;
  dlib::extract_image_chips(image, chips, face_chips);
  const std::vector<dlib::matrix<float, 0, 1>> descriptors =
      models.net(face_chips, batch_size);
  for (std::size_t index = 0; index < faces.size(); ++index) {
    const dlib::matrix<float, 0, 1> &descriptor = descriptors[index];
    faces[index].encoding.reserve(static_cast<std::size_t>(descriptor.size()));
    for (long element = 0; element < descriptor.size(); ++element)
      faces[index].encoding.push_back(descriptor(element));
  }
  return faces;
}

} // namespace pam_biometrics
