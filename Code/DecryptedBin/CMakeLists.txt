cmake_minimum_required(VERSION 3.20)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(MyProject 
        VERSION 1.0 
        LANGUAGES CXX)

set(CryptPP_ROOT ${CMAKE_SOURCE_DIR}/ThirdParty/CryptPP)

file(GLOB_RECURSE CODE_FILES CONFIGURE_DEPENDS
    "Code/*.cpp" 
    "Code/*.h"
)

add_executable(MyProject ${CODE_FILES})

target_include_directories(MyProject 
    PRIVATE 
    ${CryptPP_ROOT}/source
)

target_link_directories(MyProject 
    PRIVATE 
      ${CryptPP_ROOT}/lib
)

target_link_libraries(MyProject 
    PRIVATE 
    
    cryptlib
)