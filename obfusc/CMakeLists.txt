cmake_minimum_required(VERSION 3.20)
project(Obfusc LANGUAGES CXX)

# Build against the same LLVM major as rustc's LLVM (20). LLVM_DIR (passed on the
# command line as $(llvm-config-20 --cmakedir)) selects the exact install; LLVM's
# config-version file rejects a bare "20" request, so we pin via LLVM_DIR instead.
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Obfusc: using LLVM ${LLVM_PACKAGE_VERSION} from ${LLVM_DIR}")
if(NOT LLVM_PACKAGE_VERSION VERSION_GREATER_EQUAL 20)
  message(FATAL_ERROR "Obfusc needs LLVM 20.x (rustc's LLVM); got ${LLVM_PACKAGE_VERSION}")
endif()

add_library(Obfusc MODULE Obfusc.cpp)

target_include_directories(Obfusc SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND "${LLVM_DEFINITIONS}")
target_compile_definitions(Obfusc PRIVATE ${LLVM_DEFINITIONS_LIST})

set_target_properties(Obfusc PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
  PREFIX ""            # produce Obfusc.so, not libObfusc.so
)

# LLVM is typically built without RTTI; match it or linking/loading breaks.
if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(Obfusc PRIVATE -fno-rtti)
endif()

# A pass plugin is loaded into a process that already has LLVM; do not link LLVM
# libs into the plugin (symbols resolve from the host). Allow undefined at link.
