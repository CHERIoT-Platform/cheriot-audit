cmake_minimum_required(VERSION 3.16)

project(cheriot-policy LANGUAGES CXX)


if (DEFINED ENV{REGOCPP_REPO})
  set(REGOCPP_REPO $ENV{REGOCPP_REPO})
else ()
  set(REGOCPP_REPO "https://github.com/microsoft/rego-cpp/")
endif ()

if (DEFINED ENV{REGOCPP_TAG})
  set(REGOCPP_TAG $ENV{REGOCPP_TAG})
else ()
  set(REGOCPP_TAG "cb967637dbf7cee25117203bbdf9c10b62dfb25a")
endif()

include(FetchContent)
FetchContent_Declare(
  regocpp
  GIT_REPOSITORY ${REGOCPP_REPO}
  GIT_TAG        ${REGOCPP_TAG}
)
FetchContent_MakeAvailable(regocpp)

FetchContent_Declare(nlohmann_json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(nlohmann_json)

add_executable(cheriot-audit audit.cc)
set_property(TARGET cheriot-audit PROPERTY CXX_STANDARD 20)

target_link_libraries(cheriot-audit PRIVATE regocpp::rego)
target_link_libraries(cheriot-audit PRIVATE nlohmann_json::nlohmann_json)

enable_testing()
add_subdirectory("Tests")
