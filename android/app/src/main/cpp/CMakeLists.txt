cmake_minimum_required(VERSION 3.22.1)

project(securevault)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(securevault SHARED
    securevault_crypto.c
)

target_include_directories(securevault PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Hide symbols
set_target_properties(securevault PROPERTIES
    OUTPUT_NAME "securevault_crypto"
    VERSION 1.0.0
    SOVERSION 1
)

# Position independent code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Optimization
if(CMAKE_BUILD_TYPE MATCHES Release)
    target_compile_options(securevault PRIVATE
        -O3
        -ffunction-sections
        -fdata-sections
    )
    
    target_link_options(securevault PRIVATE
        -Wl,--gc-sections
    )
endif()