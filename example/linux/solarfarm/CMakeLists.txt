cmake_minimum_required(VERSION 3.21)

project (SolarFarmDemo)

option (COMPILE_LIB_SET "Set ioConnectCore compile to a Lib" ON)

include_directories(./core/src)

add_compile_options(-g -O0 -Wno-implicit-function-declaration)

add_executable(SolarFarmDemo main.c) 

add_subdirectory(./core)

if (COMPILE_LIB_SET)
    target_link_libraries(SolarFarmDemo ioConnectCore curl)
else()
    target_sources(SolarFarmDemo PRIVATE ${ioConnectCore_SRC})
endif()

#add_compile_options(-fsanitize=address -fsanitize-recover=address -fno-stack-protector -fno-omit-frame-pointer)
#target_link_libraries(SolarFarmDemo asan)


