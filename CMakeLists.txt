cmake_minimum_required(VERSION 3.20)

project(
    ATVResearch
    VERSION 0.1.0
    DESCRIPTION "Apple TV firmware research and binary analysis toolkit"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)

find_package(LibArchive REQUIRED)

add_library(atvresearch_core
    src/core/binary_reader.cpp
    src/ipsw/ipsw_archive.cpp
    src/macho/macho_parser.cpp
)

target_include_directories(atvresearch_core
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

if(TARGET LibArchive::LibArchive)
    target_link_libraries(
        atvresearch_core
        PUBLIC
            LibArchive::LibArchive
    )
else()
    target_include_directories(
        atvresearch_core
        PUBLIC
            ${LibArchive_INCLUDE_DIRS}
    )

    target_link_libraries(
        atvresearch_core
        PUBLIC
            ${LibArchive_LIBRARIES}
    )
endif()

if(MSVC)
    target_compile_options(
        atvresearch_core
        PRIVATE
            /W4
    )
else()
    target_compile_options(
        atvresearch_core
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )
endif()

add_executable(
    atvresearch
    src/cli/main.cpp
)

target_link_libraries(
    atvresearch
    PRIVATE
        atvresearch_core
)

enable_testing()

add_subdirectory(tests)

install(
    TARGETS atvresearch
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
