cmake_minimum_required(VERSION 3.14.0)
project(trieste VERSION 1.0.0 LANGUAGES CXX C)

include(FetchContent)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SNMALLOC_BUILD_TESTING OFF CACHE INTERNAL "Turn off snmalloc tests")
set(SNMALLOC_STATIC_LIBRARY_PREFIX "")
set(RE2_BUILD_TESTING OFF CACHE INTERNAL "Turn off RE2 tests")

FetchContent_Declare(
  snmalloc
  GIT_REPOSITORY https://github.com/microsoft/snmalloc
  GIT_TAG main
  GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(snmalloc)

FetchContent_Declare(
  re2
  GIT_REPOSITORY https://github.com/google/re2
  GIT_TAG 2022-12-01
  GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(re2)

FetchContent_Declare(
  cli11
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11
  GIT_TAG b9be5b9444772324459989177108a6a65b8b2769
  GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(cli11)

# #############################################
# Options
option(TRIESTE_BUILD_SAMPLES "Specifies whether to build the samples" ON)
option(TRIESTE_USE_QUICKJS_REGEXP "Specifies whether to use QuickJS for regexp matching" OFF)

if (TRIESTE_USE_QUICKJS_REGEXP)
  FetchContent_Declare(
    quickjs
    GIT_REPOSITORY https://github.com/bellard/quickjs
    GIT_TAG 2788d71e823b522b178db3b3660ce93689534e6d
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(quickjs)

  set(QUICKJS_RE_SRC
    ${quickjs_SOURCE_DIR}/libunicode.c
    ${quickjs_SOURCE_DIR}/libregexp.c
  )
  add_library(qjsre STATIC ${QUICKJS_RE_SRC})
  execute_process(
    COMMAND cat "${quickjs_SOURCE_DIR}/VERSION"
    OUTPUT_VARIABLE QUICKJS_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  target_compile_options(qjsre
    PRIVATE -DCONFIG_VERSION="${QUICKJS_VERSION}" -DCONFIG_BIGNUM
  )
  target_include_directories(
    qjsre PUBLIC $<BUILD_INTERFACE:${quickjs_SOURCE_DIR}>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  message(STATUS "Using QuickJS version ${QUICKJS_VERSION} for regexp matching at ${quickjs_SOURCE_DIR}")
endif()

set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)

# #############################################
# Create target and set properties
add_library(trieste INTERFACE)

# Add an alias so that library can be used inside the build tree, e.g. when testing
add_library(trieste::trieste ALIAS trieste)

# Set target properties
target_include_directories(trieste
  INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

set(TRIESTE_REGEX_IMPL re2)
set(TRIESTE_REGEXP_LIB re2)
set(TRIESTE_REGEXP_TARGET re2::re2)
if (TRIESTE_USE_QUICKJS_REGEXP)
  set(TRIESTE_REGEXP_LIB qjsre)
  set(TRIESTE_REGEXP_TARGET qjsre)
  set(TRIESTE_REGEX_IMPL qjsre)
endif()

target_link_libraries(trieste
  INTERFACE
  snmallocshim-static
  ${TRIESTE_REGEXP_TARGET}
  CLI11::CLI11
)

if (TRIESTE_USE_QUICKJS_REGEXP)
  target_compile_definitions(trieste INTERFACE TRIESTE_USE_QUICKJS_REGEXP)
endif()

target_compile_features(trieste INTERFACE cxx_std_20)

if(MSVC)
  target_compile_options(trieste INTERFACE /W4 /WX /wd5030 /bigobj)
else()
  target_compile_options(trieste INTERFACE
    -Wall -Wextra -Wpedantic -Werror -Wshadow)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  target_compile_options(trieste INTERFACE -Wmismatched-tags -fstandalone-debug)
endif()

# #############################################
# Installation instructions
set(CMAKE_INSTALL_PREFIX ${PROJECT_BINARY_DIR}/dist)

# Clear all existing files and folders from the install directory
install(CODE [[
  file(REMOVE_RECURSE ${CMAKE_INSTALL_PREFIX}/.)
  ]])

install(TARGETS trieste snmallocshim-static snmalloc ${TRIESTE_REGEXP_LIB} CLI11
  EXPORT ${PROJECT_NAME}_Targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Create a ConfigVersion.cmake file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  ${PROJECT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(${PROJECT_SOURCE_DIR}/cmake/triesteConfig.cmake.in
  ${PROJECT_BINARY_DIR}/triesteConfig.cmake
  INSTALL_DESTINATION
  ${CMAKE_INSTALL_DATAROOTDIR}/${PROJECT_NAME}/cmake
)

install(EXPORT ${PROJECT_NAME}_Targets
  FILE ${PROJECT_NAME}Targets.cmake
  NAMESPACE ${PROJECT_NAME}::
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/${PROJECT_NAME}/cmake)

install(FILES ${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
  ${PROJECT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/${PROJECT_NAME}/cmake)

install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/trieste DESTINATION include)

# #############################################
# # Exporting from the build tree
export(EXPORT ${PROJECT_NAME}_Targets
  FILE ${CMAKE_CURRENT_BINARY_DIR}/triesteTargets.cmake
  NAMESPACE trieste::)

# Register package in the User Package Registry
export(PACKAGE trieste)

# #############################################
# # Add samples
if(TRIESTE_BUILD_SAMPLES)
  enable_testing()
  add_subdirectory(samples/infix)
endif()
