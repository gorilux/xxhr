cmake_minimum_required(VERSION 3.18)

project(xxhr)

include(FetchContent)

set(BOOST_VERSION 1.72.0)
set(BOOST_COMPONENTS    
    system    
)

find_package(Boost ${BOOST_VERSION} REQUIRED COMPONENTS ${BOOST_COMPONENTS})
find_package(Threads REQUIRED)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Some container classes rely on openssl headers, but not on linking to
# the library proper.
if (NOT TARGET OpenSSL::headers)
    add_library(openssl_headers INTERFACE)
    add_library(OpenSSL::headers ALIAS openssl_headers)
    target_include_directories(openssl_headers
        INTERFACE "${OPENSSL_INCLUDE_DIR}"
    )
    if (TARGET built_openssl)
        add_dependencies(openssl_headers built_openssl)
    endif()
endif()


FetchContent_Declare(
    better-enums
    GIT_REPOSITORY https://github.com/gorilux/better-enums.git
)

FetchContent_MakeAvailable(better-enums)

file(GLOB_RECURSE lib_xxhr_sources "./xxhr/*.cpp" "./xxhr/**/*.h"  "./xxhr/**/*.hpp" "./xxhr/**/*.cpp")

add_library(xxhr STATIC ${lib_xxhr_sources} )

target_include_directories ( xxhr PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} )

target_link_libraries( xxhr PUBLIC better-enums Boost::boost Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
