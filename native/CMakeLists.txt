cmake_minimum_required(VERSION 3.18)
project(aes_decrypt C)

add_library(aes SHARED aes.c)

set_target_properties(aes PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    OUTPUT_NAME "aes"
    PREFIX "lib"
    SUFFIX ".so"
)

target_compile_options(aes PRIVATE
    -O3
    -fvisibility=hidden
    -fno-stack-protector
    -funroll-loops
    -ffast-math
)

target_link_options(aes PRIVATE
    -Wl,-O3
    -Wl,--gc-sections
    -Wl,-s
)