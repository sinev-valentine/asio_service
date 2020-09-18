project(lib)
cmake_minimum_required(VERSION 3.14.2)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -fPIC -DXMLSEC_CRYPTO_DYNAMIC_LOADING")

include_directories(
        ${Boost_INCLUDE_DIR}
        ${CMAKE_SOURCE_DIR}/libraries/fc_light/include
        /usr/lib/include/libxml2
        /usr/lib/include/xmlsec1
)

file(GLOB SRC ./*.cpp)
file(GLOB HPP ./*.hpp)

add_library(${PROJECT_NAME} ${SRC} ${HPP} )
target_link_libraries(${PROJECT_NAME}  xmlsec1 xslt xml2)
