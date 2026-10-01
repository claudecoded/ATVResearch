add_executable(
    macho_parser_test
    macho_parser_test.cpp
)

target_link_libraries(
    macho_parser_test
    PRIVATE
        atvresearch_core
)

add_test(
    NAME macho_parser_test
    COMMAND macho_parser_test
)
