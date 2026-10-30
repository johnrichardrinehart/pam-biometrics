// Face detection and encoding through dlib. The steps and parameters match
// the defaults of the face_recognition Python package, so that encodings
// from both stay comparable.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "rust/cxx.h"

namespace pam_biometrics {

struct Face;

// Holds the dlib detector, shape predictor, and network. The definition of
// the members stays in engine.cc, so that this header does not include dlib.
class Engine {
public:
  Engine();
  ~Engine();
  Engine(const Engine &) = delete;
  Engine &operator=(const Engine &) = delete;

  struct Models;
  std::unique_ptr<Models> models;
};

// Loads the 5-point shape predictor and the ResNet face recognition model.
std::unique_ptr<Engine> new_engine(rust::Str shape_predictor,
                                   rust::Str recognition_model);

// Finds the faces in an RGB frame and computes one encoding per face.
rust::Vec<Face> analyze(Engine &engine, rust::Slice<const std::uint8_t> rgb,
                        std::size_t width, std::size_t height);

} // namespace pam_biometrics
