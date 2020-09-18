project(client)
cmake_minimum_required(VERSION 3.14.2)

set(Boost_USE_STATIC_LIBS ON CACHE STRING "ON or OFF" )
set(Boost_USE_MULTITHREADED ON)
set(BOOST_ALL_DYN_LINK OFF)
find_package(Boost 1.70 REQUIRED COMPONENTS log chrono date_time filesystem log_setup program_options)
find_library(LIB_OPENSSL NAME crypto HINTS ${OPENSSL_ROOT_DIR})


include_directories(
        ${CMAKE_SOURCE_DIR}/libraries/fc_light/include
        ${Boost_INCLUDE_DIR}
        ${CMAKE_SOURCE_DIR}/app
        ${CMAKE_SOURCE_DIR}/lib
        ${CMAKE_SOURCE_DIR}/srv
        /usr/lib/include/libxml2
        /usr/lib/include/xmlsec1
)

file(GLOB SRC "*.cpp")
file(GLOB HPP ".*hpp")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/client)

add_library(${PROJECT_NAME} SHARED ${SRC} ${HPP})
target_link_libraries(${PROJECT_NAME}  fc_light  ${Boost_LIBRARIES} ssl ${LIB_OPENSSL}  lib )
