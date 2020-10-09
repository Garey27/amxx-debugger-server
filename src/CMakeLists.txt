include(AMXConfig)
include(AddAMXXPlugin)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ./amx
  ../deps
  ../deps/amtl
  ../deps/subhook
  ../deps/metamod
  ../deps/cssdk/dlls
  ../deps/cssdk/engine
  ../deps/cssdk/common
  ../deps/cssdk/public
  ../deps/cssdk/game_shared
  ../deps/cssdk/pm_shared  
  ../deps/brynet/include
)

if(MSVC)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

set(DEBUGGER_SOURCES
    utlmemory.h
    utlbuffer.h
    utlbuffer.cpp
    plugin.h
    plugin.def
    plugin.cpp
    debugger.h
    debugger.cpp
    amxxmodule.h
    amxxmodule.cpp
    moduleconfig.h
)

add_amxx_module(debugger ${DEBUGGER_SOURCES})

add_subdirectory(amx)
target_link_libraries(debugger subhook amx)
if(WIN32)
  target_link_libraries(debugger ws2_32)
elseif(UNIX)
  set(CMAKE_CXX_FLAGS "-fpermissive")
  find_package(Threads REQUIRED)
  target_link_libraries(debugger pthread -static-libgcc -static-libstdc++)
endif()
install(TARGETS debugger LIBRARY DESTINATION ".")

set_target_properties(debugger PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
foreach(config ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${config} config)
    set_target_properties(debugger PROPERTIES LIBRARY_OUTPUT_DIRECTORY_${config} "${CMAKE_BINARY_DIR}")
endforeach()
