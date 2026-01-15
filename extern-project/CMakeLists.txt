cmake_minimum_required(VERSION 3.16)
project(consumer_example CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
  your_tool_name
  GIT_REPOSITORY https://github.com/CoreTrace/your_tool_name.git
  GIT_TAG main
)

FetchContent_MakeAvailable(your_tool_name)

add_executable(sa_consumer src/main.cpp)

target_link_libraries(sa_consumer
    PRIVATE
        coretrace::your_tool_name_lib
)
