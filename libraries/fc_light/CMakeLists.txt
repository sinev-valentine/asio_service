project( fc_light  )

cmake_minimum_required(VERSION 3.14.2)

set(CMAKE_CXX_FLAGS "-std=c++14 -fPIC")

if (NOT MSVC)
    if ( LIBCXX_BUILD )
        set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -stdlib=libc++" )
    endif()
else()
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc " )
endif()

SET(BOOST_COMPONENTS)
LIST(APPEND BOOST_COMPONENTS date_time filesystem chrono log)

SET( Boost_USE_STATIC_LIBS ON CACHE STRING "ON or OFF" )

SET(BOOST_ROOT $ENV{BOOST_ROOT})
set(Boost_USE_MULTITHREADED ON)
set(BOOST_ALL_DYN_LINK OFF)


FIND_PACKAGE(Boost 1.70 REQUIRED COMPONENTS ${BOOST_COMPONENTS})
SET(BOOST_LIBRARIES_TEMP ${Boost_LIBRARIES})
SET(Boost_LIBRARIES ${BOOST_LIBRARIES_TEMP} ${Boost_LIBRARIES})

include_directories(
        "./include"
        "${OPENSSL_ROOT_DIR}/include"
        "/usr/include/libcxxabi"
        ${Boost_INCLUDE_DIR})


file(GLOB FC_LIGHT_SOURCES "./src/*.cpp" "./src/*/*.cpp")
file(GLOB FC_LIGHT_INCLUDE "./include/fc_light/*.hpp" "./include/fc_light/*/*.hpp")

add_library(fc_light STATIC ${FC_LIGHT_SOURCES} ${FC_LIGHT_INCLUDE} )

target_link_libraries(fc_light ${Boost_LIBRARIES})
