set(CMAKE_GENERATOR_PLATFORM Win32)

if(CMAKE_VERSION VERSION_LESS "3.15")
  message(FATAL_ERROR "Minimum CMake 3.15 is required (got ${CMAKE_VERSION})")
endif()

add_compile_definitions(${PROJECT_NAME} PRIVATE _WIN32_WINNT=0x0501)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)

set(flags)
set(relflags)

list(APPEND flags /MP)
list(APPEND relflags /Gw /GS- /GL /Gy)

list(JOIN flags " " flags)
set(CMAKE_C_FLAGS_INIT ${flags})
set(CMAKE_CXX_FLAGS_INIT ${flags})

list(JOIN relflags " " relflags)
set(CMAKE_C_FLAGS_RELEASE_INIT ${relflags})
set(CMAKE_CXX_FLAGS_RELEASE_INIT ${relflags})