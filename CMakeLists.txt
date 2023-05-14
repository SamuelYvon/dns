cmake_minimum_required(VERSION 3.25)
project(dns C)

set(CMAKE_C_STANDARD 23)

add_executable(dns main.c)
target_sources(dns PRIVATE main.c)

if (MSVC)
    target_compile_options(dns PRIVATE /W4 /WX)
else ()
    target_compile_options(dns PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif ()

