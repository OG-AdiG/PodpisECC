cmake_minimum_required(VERSION 3.16)
project(PodpisECC VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Strawberry Perl / lokalne instalacje OpenSSL na Windows
if(WIN32 AND NOT DEFINED OPENSSL_ROOT_DIR)
    foreach(_candidate
        "C:/Strawberry/c"
        "C:/Program Files/OpenSSL-Win64"
        "C:/Program Files/OpenSSL"
        "C:/OpenSSL-Win64")
        if(EXISTS "${_candidate}/include/openssl/ssl.h")
            set(OPENSSL_ROOT_DIR "${_candidate}" CACHE PATH "OpenSSL root")
            break()
        endif()
    endforeach()
endif()

find_package(OpenSSL REQUIRED)

add_executable(podpis_ecc
    src/main.cpp
    src/keys.cpp
    src/hash.cpp
    src/signature.cpp
    src/benchmark.cpp
    src/utils.cpp
)

target_include_directories(podpis_ecc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

target_link_libraries(podpis_ecc PRIVATE
    OpenSSL::Crypto
)

if(WIN32)
    target_link_libraries(podpis_ecc PRIVATE ws2_32)
endif()

if(MSVC)
    target_compile_options(podpis_ecc PRIVATE /W4)
else()
    target_compile_options(podpis_ecc PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(podpis_ecc PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Kopiuj frontend obok binarki (wygodne uruchamianie z build/bin)
add_custom_command(TARGET podpis_ecc POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/web"
        "$<TARGET_FILE_DIR:podpis_ecc>/web"
    COMMENT "Kopiowanie UI web do katalogu binarki"
)

message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
