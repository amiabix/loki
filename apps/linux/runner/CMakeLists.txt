cmake_minimum_required(VERSION 3.13)
project(runner LANGUAGES CXX)

# Define the application target. To change its name, change BINARY_NAME in the
# top-level CMakeLists.txt, not the value here, or `flutter run` will no longer
# work.
#
# Any new source files that you add to the application should be added here.
add_executable(${BINARY_NAME}
  "main.cc"
  "my_application.cc"
  "wallet_channel.cc"
  "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
)

# Apply the standard set of build settings. This can be removed for applications
# that need different build settings.
apply_standard_settings(${BINARY_NAME})
target_compile_features(${BINARY_NAME} PRIVATE cxx_std_17)

# Add preprocessor definitions for the application ID.
add_definitions(-DAPPLICATION_ID="${APPLICATION_ID}")

# Add dependency libraries. Add any application-specific dependencies here.
pkg_check_modules(FONTCONFIG REQUIRED IMPORTED_TARGET fontconfig)
target_link_libraries(${BINARY_NAME} PRIVATE flutter)
target_link_libraries(${BINARY_NAME} PRIVATE PkgConfig::GTK PkgConfig::FONTCONFIG)

target_include_directories(${BINARY_NAME} PRIVATE "${CMAKE_SOURCE_DIR}")

# Cargo tracks Rust and vendored dependencies; only relink when the archive changes.
find_program(CARGO cargo)
if(NOT CARGO)
  message(FATAL_ERROR "Install Rust and add cargo to PATH before building LokiSigner")
endif()
find_package(Threads REQUIRED)
get_filename_component(CORE "${CMAKE_CURRENT_SOURCE_DIR}/../../../core" ABSOLUTE)
set(RUST_TARGET_DIR "${CORE}/target")
if(DEFINED ENV{CARGO_TARGET_DIR})
  get_filename_component(RUST_TARGET_DIR "$ENV{CARGO_TARGET_DIR}" ABSOLUTE BASE_DIR "${CORE}")
endif()
set(RUST_PROFILE "release")
set(RUST_FLAGS --release)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(RUST_PROFILE "debug")
  set(RUST_FLAGS)
endif()
set(RUST_LIBRARY "${RUST_TARGET_DIR}/${RUST_PROFILE}/libloki_poc.a")
add_custom_target(loki_core
  COMMAND "${CARGO}" build --locked --lib --features linux-desktop
    --target-dir "${RUST_TARGET_DIR}" ${RUST_FLAGS}
  WORKING_DIRECTORY "${CORE}"
  BYPRODUCTS "${RUST_LIBRARY}"
  VERBATIM
)
add_dependencies(${BINARY_NAME} loki_core)
target_link_libraries(${BINARY_NAME} PRIVATE "${RUST_LIBRARY}" Threads::Threads ${CMAKE_DL_LIBS} m)
