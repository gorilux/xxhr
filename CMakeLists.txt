cmake_minimum_required(VERSION 3.18)

project(xxhr)

set(BOOST_VERSION 1.72.0)
set(BOOST_COMPONENTS    
    system    
)

find_package(Boost ${BOOST_VERSION} REQUIRED COMPONENTS ${BOOST_COMPONENTS})
find_package(Threads REQUIRED)

find_package(OpenSSL REQUIRED)

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


add_library(xxhr INTERFACE)

target_include_directories ( xxhr INTERFACE xxhr/)

target_link_libraries( xxhr INTERFACE Boost::boost Threads::Threads OpenSSL::headers)
