cmake_minimum_required(VERSION 3.16)

project(cheriot-policy LANGUAGES CXX)

include(FetchContent)
FetchContent_Declare(
  regocpp
  GIT_REPOSITORY https://github.com/microsoft/rego-cpp.git
  GIT_TAG        cb967637dbf7cee25117203bbdf9c10b62dfb25a
)
FetchContent_MakeAvailable(regocpp)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(json)


find_package(nlohmann_json 3.2.0 REQUIRED)



add_executable(cheriot-audit audit.cc)
set_property(TARGET cheriot-audit PROPERTY CXX_STANDARD 20)

target_link_libraries(cheriot-audit PRIVATE regocpp::rego)
target_link_libraries(cheriot-audit PRIVATE nlohmann_json::nlohmann_json)
